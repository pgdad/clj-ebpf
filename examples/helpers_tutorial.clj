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
   9. Context Structure Offsets (clj-ebpf.ctx)
   10. Network Byte Order Conversion (dsl/htons, ntohs, etc.)
   11. Socket Key Building (maps/build-sock-key)

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
            [clj-ebpf.ctx :as ctx]
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
;; Section 9: Context Structure Offsets
;; ============================================================================

(defn demo-context-offsets
  "Demonstrate BPF context structure offsets.

   Pre-defined offsets for accessing fields in BPF context structures
   eliminate manual offset calculations and reduce errors."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 9: CONTEXT STRUCTURE OFFSETS")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Purpose: Access BPF context fields without manual offset calculations")
  (println "         Covers all major program types and protocol headers\n")

  ;; Example 1: bpf_sock_ops structure
  (println "Example 1: bpf_sock_ops Structure (SOCK_OPS programs)")
  (println "-----------------------------------------------------")
  (println "struct bpf_sock_ops field offsets:\n")
  (doseq [[field offset] (take 10 (sort-by val ctx/bpf-sock-ops))]
    (printf "  %-20s offset %3d\n" (name field) offset))
  (println "  ... and" (- (count ctx/bpf-sock-ops) 10) "more fields\n")

  (println "Usage in BPF program:")
  (println "  ;; Load operation code from sock_ops context")
  (println "  (dsl/ldx :w :r2 :r1 (:op ctx/bpf-sock-ops))")
  (println "  ;; Load local port (note: HOST byte order)")
  (println "  (dsl/ldx :w :r2 :r1 (:local-port ctx/bpf-sock-ops))")
  (println "  ;; Load remote port (note: NETWORK byte order)")
  (println "  (dsl/ldx :w :r2 :r1 (:remote-port ctx/bpf-sock-ops))\n")

  ;; Example 2: bpf_sock structure
  (println "Example 2: bpf_sock Structure")
  (println "-----------------------------")
  (println "struct bpf_sock field offsets:\n")
  (doseq [[field offset] (sort-by val ctx/bpf-sock)]
    (printf "  %-20s offset %3d\n" (name field) offset))
  (println)

  ;; Example 3: Re-exported structures
  (println "Example 3: Re-exported Context Structures")
  (println "------------------------------------------")
  (println "clj-ebpf.ctx re-exports offsets from specialized modules:\n")
  (println "  ctx/sk-buff    - __sk_buff for TC/Socket Filter programs")
  (printf  "                   (%d fields: len, mark, data, data-end, etc.)\n"
           (count ctx/sk-buff))
  (println "  ctx/xdp-md     - xdp_md for XDP programs")
  (printf  "                   (%d fields: data, data-end, ingress-ifindex, etc.)\n"
           (count ctx/xdp-md))
  (println "  ctx/sk-msg     - sk_msg_md for SK_MSG programs")
  (printf  "                   (%d fields: data, data-end, family, etc.)\n"
           (count ctx/sk-msg))
  (println "  ctx/bpf-sk-lookup - bpf_sk_lookup for SK_LOOKUP programs")
  (printf  "                   (%d fields: sk, family, protocol, etc.)\n\n"
           (count ctx/bpf-sk-lookup))

  ;; Example 4: Protocol header offsets
  (println "Example 4: Protocol Header Offsets")
  (println "----------------------------------")
  (println "Pre-defined offsets for packet parsing:\n")

  (println "  Ethernet Header (ctx/ethernet-offsets):")
  (doseq [[field offset] ctx/ethernet-offsets]
    (printf "    %-15s offset %2d\n" (name field) offset))
  (println)

  (println "  IPv4 Header (ctx/ipv4-offsets):")
  (doseq [[field offset] (take 6 (sort-by val ctx/ipv4-offsets))]
    (printf "    %-15s offset %2d\n" (name field) offset))
  (println)

  (println "  TCP Header (ctx/tcp-offsets):")
  (doseq [[field offset] (take 4 (sort-by val ctx/tcp-offsets))]
    (printf "    %-15s offset %2d\n" (name field) offset))
  (println)

  ;; Example 5: Header size constants
  (println "Example 5: Header Size Constants")
  (println "--------------------------------")
  (println "  ctx/ethernet-header-size:  " ctx/ethernet-header-size "bytes")
  (println "  ctx/ipv4-header-min-size:  " ctx/ipv4-header-min-size "bytes (no options)")
  (println "  ctx/ipv6-header-size:      " ctx/ipv6-header-size "bytes")
  (println "  ctx/tcp-header-min-size:   " ctx/tcp-header-min-size "bytes (no options)")
  (println "  ctx/udp-header-size:       " ctx/udp-header-size "bytes\n")

  ;; Example 6: Utility constants
  (println "Example 6: Protocol Constants")
  (println "-----------------------------")
  (println "  Address Families (ctx/address-family):")
  (doseq [[name val] (take 4 ctx/address-family)]
    (printf "    %-10s %d\n" (clojure.core/name name) val))
  (println)

  (println "  Socket Types (ctx/socket-type):")
  (doseq [[name val] (take 3 ctx/socket-type)]
    (printf "    %-10s %d\n" (clojure.core/name name) val))
  (println)

  (println "  IP Protocols (ctx/ip-protocol):")
  (doseq [[name val] ctx/ip-protocol]
    (printf "    %-10s %d\n" (clojure.core/name name) val)))

;; ============================================================================
;; Section 10: Network Byte Order Conversion
;; ============================================================================

(defn demo-byte-order-conversion
  "Demonstrate network byte order conversion helpers.

   Network protocols use big-endian byte order, while most CPUs use
   little-endian. These helpers convert between host and network order."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 10: NETWORK BYTE ORDER CONVERSION")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Purpose: Convert between host and network byte order")
  (println "         Required for port numbers and IP addresses\n")

  ;; Example 1: BPF instruction generation
  (println "Example 1: BPF Instructions for Byte Order Conversion")
  (println "------------------------------------------------------")
  (println "Generate BPF instructions for in-program byte swapping:\n")

  (let [htons-insn (dsl/htons :r7)
        htonl-insn (dsl/htonl :r5)]
    (println "  16-bit conversion (ports):")
    (println "    (dsl/htons :r7) - host to network short")
    (println "    (dsl/ntohs :r7) - network to host short (same operation)")
    (printf  "    Generates %d bytes of BPF bytecode\n\n" (count htons-insn))

    (println "  32-bit conversion (IPv4 addresses):")
    (println "    (dsl/htonl :r5) - host to network long")
    (println "    (dsl/ntohl :r5) - network to host long (same operation)")
    (printf  "    Generates %d bytes of BPF bytecode\n\n" (count htonl-insn)))

  ;; Example 2: Compile-time value conversion
  (println "Example 2: Compile-Time Value Conversion")
  (println "-----------------------------------------")
  (println "Convert values in Clojure before encoding in instructions:\n")

  (println "  Port conversion (16-bit):")
  (println "    (dsl/htons-val 80)   =>" (format "0x%04X" (dsl/htons-val 80)))
  (println "    (dsl/htons-val 8080) =>" (format "0x%04X" (dsl/htons-val 8080)))
  (println "    (dsl/htons-val 443)  =>" (format "0x%04X" (dsl/htons-val 443)))
  (println)

  (println "  Symmetry verification:")
  (println "    (dsl/ntohs-val (dsl/htons-val 8080)) =" (dsl/ntohs-val (dsl/htons-val 8080)))
  (println)

  (println "  IPv4 address conversion (32-bit):")
  (println "    127.0.0.1   (0x7F000001):")
  (println "      (dsl/htonl-val 0x7F000001) =>" (format "0x%08X" (dsl/htonl-val 0x7F000001)))
  (println "    192.168.1.1 (0xC0A80101):")
  (println "      (dsl/htonl-val 0xC0A80101) =>" (format "0x%08X" (dsl/htonl-val 0xC0A80101)))
  (println)

  ;; Example 3: Practical usage
  (println "Example 3: Practical Usage - Port Matching")
  (println "-------------------------------------------")
  (let [program [(dsl/ldx :w :r2 :r1 (:src-port ctx/tcp-offsets))  ; Load port
                 (dsl/htons :r2)                                   ; Convert to host order
                 (dsl/jmp-imm :jne :r2 80 3)                      ; Compare with port 80
                 (dsl/mov :r0 1)                                   ; Match: XDP_DROP
                 (dsl/exit-insn)
                 (dsl/mov :r0 2)                                   ; No match: XDP_PASS
                 (dsl/exit-insn)]]
    (println "Match packets to port 80 (HTTP):")
    (println)
    (println "  ;; Load source port (network byte order)")
    (println "  (dsl/ldx :w :r2 :r1 (:src-port ctx/tcp-offsets))")
    (println "  ;; Convert to host byte order")
    (println "  (dsl/htons :r2)")
    (println "  ;; Compare with port 80")
    (println "  (dsl/jmp-imm :jne :r2 80 3)")
    (println)
    (printf  "  Total: %d instructions\n\n" (count program)))

  ;; Example 4: Byte order notes
  (println "Example 4: Important Byte Order Notes")
  (println "-------------------------------------")
  (println "Different BPF contexts have DIFFERENT byte orders for ports:\n")
  (println "  Context          remote_port    local_port")
  (println "  -------          -----------    ----------")
  (println "  bpf_sock_ops     NETWORK        HOST (!)")
  (println "  bpf_sock         NETWORK        HOST (!)")
  (println "  __sk_buff        NETWORK        HOST (!)")
  (println "  sk_msg_md        NETWORK        HOST (!)")
  (println "  bpf_sk_lookup    HOST           HOST")
  (println)
  (println "IMPORTANT: local_port is usually HOST byte order!")
  (println "           Only convert remote_port before comparison."))

;; ============================================================================
;; Section 11: Socket Key Building Helpers
;; ============================================================================

(defn demo-socket-key-helpers
  "Demonstrate socket key building helpers for sockmap/sockhash.

   These helpers generate instruction sequences to extract connection
   tuples (4-tuple or 5-tuple) from BPF context structures."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 11: SOCKET KEY BUILDING HELPERS")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Purpose: Build socket keys for sockmap/sockhash operations")
  (println "         Automatically extract connection tuples from context\n")

  ;; Example 1: Supported context types
  (println "Example 1: Supported Context Types")
  (println "----------------------------------")
  (println "maps/context-key-offsets defines offsets for each context type:\n")
  (doseq [[ctx-type offsets] maps/context-key-offsets]
    (printf "  %-12s remote_ip4: %3d  local_ip4: %3d  remote_port: %3d  local_port: %3d\n"
            (name ctx-type)
            (:remote-ip4 offsets)
            (:local-ip4 offsets)
            (:remote-port offsets)
            (:local-port offsets)))
  (println)

  ;; Example 2: Building a 4-tuple key
  (println "Example 2: Building a 4-Tuple IPv4 Key")
  (println "--------------------------------------")
  (let [instrs (maps/build-sock-key :r6 -16 :sock-ops)]
    (println "Build 16-byte key (remote_ip + local_ip + ports) from sock_ops:\n")
    (println "  (maps/build-sock-key :r6 -16 :sock-ops)")
    (println)
    (println "  Parameters:")
    (println "    :r6        - Register containing context pointer")
    (println "    -16        - Stack offset to store key (16 bytes needed)")
    (println "    :sock-ops  - Context type (bpf_sock_ops)")
    (println)
    (println "  Key layout on stack:")
    (println "    offset+0:  remote_ip4  (4 bytes)")
    (println "    offset+4:  local_ip4   (4 bytes)")
    (println "    offset+8:  remote_port (4 bytes)")
    (println "    offset+12: local_port  (4 bytes)")
    (println)
    (printf  "  Generated %d instructions (%d bytes)\n\n"
             (count instrs) (* 8 (count instrs))))

  ;; Example 3: IPv6 key building
  (println "Example 3: Building an IPv6 Key")
  (println "-------------------------------")
  (let [instrs (maps/build-sock-key-ipv6 :r6 -48 :sock-ops)]
    (println "Build 40-byte key for IPv6 connections:\n")
    (println "  (maps/build-sock-key-ipv6 :r6 -48 :sock-ops)")
    (println)
    (println "  Key layout on stack:")
    (println "    offset+0:  remote_ip6  (16 bytes)")
    (println "    offset+16: local_ip6   (16 bytes)")
    (println "    offset+32: remote_port (4 bytes)")
    (println "    offset+36: local_port  (4 bytes)")
    (println)
    (printf  "  Generated %d instructions (%d bytes)\n\n"
             (count instrs) (* 8 (count instrs))))

  ;; Example 4: Complete sock_ops to sockmap lookup pattern
  (println "Example 4: Complete SOCK_OPS to SOCKMAP Pattern")
  (println "-----------------------------------------------")
  (let [program (concat
                  ;; Save context
                  [(dsl/mov-reg :r6 :r1)]

                  ;; Build 4-tuple key at stack[-16]
                  (maps/build-sock-key :r6 -16 :sock-ops)

                  ;; Look up in sockmap (fd=10)
                  (maps/build-map-lookup 10 -16)

                  ;; Check if found
                  [(asm/jmp-imm :jeq :r0 0 :not-found)]

                  ;; Found - do something with socket
                  [(dsl/mov :r0 1)  ; SK_PASS
                   (dsl/exit-insn)]

                  ;; Not found
                  [(asm/label :not-found)
                   (dsl/mov :r0 0)  ; SK_DROP
                   (dsl/exit-insn)])
        bytecode (asm/assemble-with-labels program)]
    (println "SOCK_OPS program that looks up connection in sockmap:\n")
    (println "  (concat")
    (println "    ;; Save context")
    (println "    [(dsl/mov-reg :r6 :r1)]")
    (println "    ;; Build key")
    (println "    (maps/build-sock-key :r6 -16 :sock-ops)")
    (println "    ;; Lookup in sockmap")
    (println "    (maps/build-map-lookup sockmap-fd -16)")
    (println "    ;; Handle result...")
    (println "    ...)")
    (println)
    (printf  "  Total: %d instructions (%d bytes)\n\n"
             (/ (count bytecode) 8) (count bytecode)))

  ;; Example 5: SK_MSG redirect pattern
  (println "Example 5: SK_MSG Redirect Pattern")
  (println "----------------------------------")
  (let [sk-msg-key (maps/build-sock-key :r6 -16 :sk-msg)]
    (println "Build key from sk_msg context for message redirection:\n")
    (println "  ;; In SK_MSG program, redirect message to peer socket")
    (println "  (concat")
    (println "    ;; Context is already in r1")
    (println "    [(dsl/mov-reg :r6 :r1)]")
    (println "    ;; Build key from sk_msg context")
    (println "    (maps/build-sock-key :r6 -16 :sk-msg)")
    (println "    ;; Look up peer socket in sockhash")
    (println "    ;; ... redirect logic ...")
    (println "    )")
    (println)
    (printf  "  Key building: %d instructions\n" (count sk-msg-key))))

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
  (demo-context-offsets)
  (demo-byte-order-conversion)
  (demo-socket-key-helpers)
  (demo-complete-xdp-firewall)

  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Tutorial Complete!")
  (println "\nFor more information:")
  (println "  - See docs/guides/helpers-guide.md")
  (println "  - Run individual examples in the examples/ directory")
  (println "  - Check test files for comprehensive API coverage")
  (println (apply str (repeat 70 "=")) "\n"))
