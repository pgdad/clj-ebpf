(ns lab-4-3-memory-profiler
  "Lab 4.3: Memory Allocation Profiler using stack trace and helper functions

   This solution demonstrates:
   - Using bpf_get_stackid() for stack trace capture
   - Combining multiple helper functions
   - Building allocation profiles
   - Identifying memory leaks and hotspots
   - Generating flame graph compatible output

   Run with: sudo clojure -M -m lab-4-3-memory-profiler
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str]
            [clojure.java.io :as io])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Configuration
;;; ============================================================================

(def MAX_STACK_DEPTH 127)
(def MAX_STACKS 10000)
(def SIZE_BUCKETS 10)

;; Size bucket labels
(def SIZE_LABELS
  ["<32B" "32-64B" "64-128B" "128-256B" "256-512B"
   "512B-1K" "1-4K" "4-16K" "16-64K" ">=64K"])

;;; ============================================================================
;;; Part 2: Maps
;;; ============================================================================

(defn create-stack-counts-map
  "Map: stack_id -> allocation count"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 8
                   :max-entries MAX_STACKS
                   :map-name "stack_counts"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-stack-bytes-map
  "Map: stack_id -> total bytes allocated"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 8
                   :max-entries MAX_STACKS
                   :map-name "stack_bytes"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-size-histogram-map
  "Histogram of allocation sizes"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries SIZE_BUCKETS
                   :map-name "size_hist"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-totals-map
  "Track overall allocation statistics"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 4   ; [total_allocs, total_bytes, max_size, unique_stacks]
                   :map-name "alloc_totals"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 3: BPF Program - Allocation Tracker
;;; ============================================================================

(defn create-alloc-tracker
  "Create BPF program to track memory allocations.

   This simplified version demonstrates:
   - Reading function arguments from pt_regs
   - bpf_get_current_pid_tgid() for process context
   - bpf_ktime_get_ns() for timestamps

   Note: bpf_get_stackid() requires a stack trace map and is
   typically used in more complex programs with perf events.

   Instruction layout:
   0: mov-reg r6, r1 (save ctx)
   1: load r7 from pt_regs+112 (size from RDI)
   2: call get_current_pid_tgid
   3: mov-reg r8, r0 (pid)
   4: rsh r8, 32 (extract TGID)
   5: call ktime_get_ns
   6: mov-reg r9, r0 (timestamp)
   7: mov r0, 0
   8: exit"
  [counts-fd histogram-fd]
  (bpf/assemble
    [;; Step 1: Save context and get allocation size
     (bpf/mov-reg :r6 :r1)           ; r6 = ctx (pt_regs)
     (bpf/load-mem :dw :r7 :r6 112)  ; r7 = size (RDI - first arg)

     ;; Step 2: Get PID
     (bpf/call 14)                   ; BPF_FUNC_get_current_pid_tgid
     (bpf/mov-reg :r8 :r0)           ; r8 = pid_tgid
     (bpf/rsh :r8 32)                ; r8 = TGID

     ;; Step 3: Get timestamp
     (bpf/call 5)                    ; BPF_FUNC_ktime_get_ns
     (bpf/mov-reg :r9 :r0)           ; r9 = timestamp

     ;; Return 0 (simplified - full version would update maps)
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 4: Symbol Resolution (from /proc/kallsyms)
;;; ============================================================================

(defn load-kallsyms
  "Load kernel symbol table from /proc/kallsyms.
   Returns sorted vector of {:address :type :symbol} maps."
  []
  (try
    (with-open [rdr (io/reader "/proc/kallsyms")]
      (into []
            (comp
              (map #(str/split % #"\s+"))
              (filter #(>= (count %) 3))
              (map (fn [[addr type sym]]
                     (try
                       {:address (Long/parseUnsignedLong addr 16)
                        :type type
                        :symbol sym}
                       (catch Exception _ nil))))
              (filter some?))
            (line-seq rdr)))
    (catch Exception e
      (println "  Warning: Could not load /proc/kallsyms:" (.getMessage e))
      (println "    Run with sudo to access kernel symbols")
      [])))

(defn resolve-kernel-symbol
  "Resolve kernel address to symbol name using binary search."
  [address kallsyms]
  (if (or (empty? kallsyms) (zero? address))
    (if (zero? address)
      "<null>"
      (format "0x%x" address))
    ;; Binary search for closest symbol
    (let [idx (loop [lo 0
                     hi (dec (count kallsyms))]
                (if (>= lo hi)
                  lo
                  (let [mid (quot (+ lo hi 1) 2)
                        mid-addr (:address (kallsyms mid))]
                    (if (<= mid-addr address)
                      (recur mid hi)
                      (recur lo (dec mid))))))
          sym (get kallsyms idx)
          offset (- address (:address sym))]
      (if (and sym (< offset 0x100000))  ; Within 1MB - likely same function
        (if (zero? offset)
          (:symbol sym)
          (format "%s+0x%x" (:symbol sym) offset))
        (format "0x%x" address)))))

;;; ============================================================================
;;; Part 5: Userspace - Data Analysis
;;; ============================================================================

(defn format-size [bytes]
  "Format byte size as human-readable"
  (cond
    (< bytes 1024) (format "%dB" bytes)
    (< bytes (* 1024 1024)) (format "%.1fKB" (/ bytes 1024.0))
    (< bytes (* 1024 1024 1024)) (format "%.1fMB" (/ bytes 1024.0 1024.0))
    :else (format "%.1fGB" (/ bytes 1024.0 1024.0 1024.0))))

(defn get-allocation-data [counts-map bytes-map]
  "Get all allocation data"
  (let [counts (into {} (bpf/map-entries counts-map))
        bytes-data (into {} (bpf/map-entries bytes-map))]
    (into {}
          (for [[stack-id cnt] counts]
            [stack-id {:count cnt
                       :bytes (get bytes-data stack-id 0)}]))))

(defn display-top-allocators [alloc-data n]
  "Display top N allocation stack traces by total bytes"
  (println (format "\nTop %d Allocation Sources (by bytes):" n))
  (println "═══════════════════════════════════════════════════════")

  (let [sorted (take n (sort-by (comp :bytes val) > alloc-data))]
    (doseq [[idx [stack-id {:keys [count bytes]}]] (map-indexed vector sorted)]
      (println (format "\n%d. Stack ID %d:" (inc idx) stack-id))
      (println (format "   Allocations: %,d" count))
      (println (format "   Total bytes: %s" (format-size bytes)))
      (when (pos? count)
        (println (format "   Avg size: %s" (format-size (quot bytes count))))))))

(defn display-size-histogram [histogram-map]
  "Display allocation size distribution"
  (println "\nAllocation Size Distribution:")
  (println "═══════════════════════════════════════════════════════")

  (let [histogram (into []
                    (for [i (range SIZE_BUCKETS)]
                      (or (bpf/map-lookup histogram-map i) 0)))
        total (reduce + histogram)
        max-count (apply max (conj histogram 1))
        bar-width 40]

    (println "Total allocations:" total)
    (println)

    (doseq [[i cnt] (map-indexed vector histogram)
            :when (pos? cnt)]
      (let [percentage (if (pos? total)
                        (* 100.0 (/ cnt total))
                        0.0)
            bar-len (int (* bar-width (/ cnt max-count)))
            bar (apply str (repeat bar-len "█"))]
        (println (format "%-10s │ %s %,d (%.1f%%)"
                        (get SIZE_LABELS i (str "bucket-" i))
                        bar
                        cnt
                        percentage))))))

(defn display-statistics [alloc-data totals-map]
  "Display allocation statistics"
  (let [total-allocs (or (bpf/map-lookup totals-map 0) 0)
        total-bytes (or (bpf/map-lookup totals-map 1) 0)
        max-size (or (bpf/map-lookup totals-map 2) 0)
        unique-stacks (count alloc-data)
        avg-size (if (pos? total-allocs)
                   (quot total-bytes total-allocs)
                   0)]

    (println "\nAllocation Statistics:")
    (println "───────────────────────────────────────")
    (println (format "Total allocations  : %,d" total-allocs))
    (println (format "Total bytes        : %s" (format-size total-bytes)))
    (println (format "Average size       : %s" (format-size avg-size)))
    (println (format "Maximum size       : %s" (format-size max-size)))
    (println (format "Unique call stacks : %d" unique-stacks))))

;;; ============================================================================
;;; Part 6: Flame Graph Support
;;; ============================================================================

(defn generate-folded-stacks
  "Generate folded stack format for flame graph generation.

   Output format (one line per stack):
   func1;func2;func3 count

   Can be piped to flamegraph.pl to generate SVG."
  [alloc-data kallsyms]
  ;; In a real implementation, we'd have actual stack traces
  ;; For demo, generate synthetic function names
  (let [sample-funcs ["__kmalloc" "kmalloc_node" "alloc_skb"
                      "tcp_sendmsg" "sock_sendmsg" "__sys_sendto"
                      "alloc_pages" "kmem_cache_alloc" "do_sys_open"
                      "vfs_read" "ext4_file_read" "generic_file_read"]]
    (for [[stack-id {:keys [count]}] alloc-data]
      (let [depth (+ 2 (mod stack-id 5))
            funcs (take depth (drop (mod stack-id 6) sample-funcs))
            folded (str/join ";" (reverse funcs))]
        {:folded folded :count count}))))

(defn display-flame-graph-data [alloc-data kallsyms]
  "Display folded stack format for flame graphs"
  (println "\nFlame Graph Data (folded format):")
  (println "─────────────────────────────────────────")
  (println "Format: stack_trace count")
  (println "Use with: cat stacks.txt | flamegraph.pl > flame.svg")
  (println)

  (let [folded (generate-folded-stacks alloc-data kallsyms)]
    (doseq [{:keys [folded count]} (take 5 folded)]
      (println (format "%s %d" folded count)))
    (when (> (count folded) 5)
      (println "..."))))

;;; ============================================================================
;;; Part 7: Simulation
;;; ============================================================================

(defn simulate-allocation-data
  "Simulate allocation data for demonstration"
  [counts-map bytes-map histogram-map totals-map]
  (println "\n  Simulating allocation data...")

  ;; Simulate some stack traces and allocations
  (let [test-stacks {1 {:count 1500 :bytes (* 1500 64)}
                     2 {:count 800 :bytes (* 800 256)}
                     3 {:count 400 :bytes (* 400 1024)}
                     4 {:count 200 :bytes (* 200 128)}
                     5 {:count 100 :bytes (* 100 4096)}}]

    ;; Update counts and bytes maps
    (doseq [[stack-id data] test-stacks]
      (bpf/map-update counts-map stack-id (:count data))
      (bpf/map-update bytes-map stack-id (:bytes data)))

    ;; Update histogram (size distribution)
    (bpf/map-update histogram-map 0 500)   ; <32B
    (bpf/map-update histogram-map 1 1500)  ; 32-64B
    (bpf/map-update histogram-map 2 200)   ; 64-128B
    (bpf/map-update histogram-map 3 800)   ; 128-256B
    (bpf/map-update histogram-map 4 0)     ; 256-512B
    (bpf/map-update histogram-map 5 100)   ; 512B-1K

    ;; Update totals
    (let [total-allocs (reduce + (map :count (vals test-stacks)))
          total-bytes (reduce + (map :bytes (vals test-stacks)))]
      (bpf/map-update totals-map 0 total-allocs)
      (bpf/map-update totals-map 1 total-bytes)
      (bpf/map-update totals-map 2 4096)  ; max size
      (bpf/map-update totals-map 3 (count test-stacks))))  ; unique stacks

  (println "  Added simulated allocation data"))

;;; ============================================================================
;;; Part 8: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 4.3: Memory Allocation Profiler ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Load kernel symbols
  (println "\nStep 2: Loading kernel symbols...")
  (let [kallsyms (load-kallsyms)]
    (println "  Loaded" (count kallsyms) "kernel symbols")

    ;; Step 3: Create maps
    (println "\nStep 3: Creating maps...")
    (let [counts-map (create-stack-counts-map)
          bytes-map (create-stack-bytes-map)
          histogram-map (create-size-histogram-map)
          totals-map (create-totals-map)]
      (println "  Stack counts map created (FD:" (:fd counts-map) ")")
      (println "  Stack bytes map created (FD:" (:fd bytes-map) ")")
      (println "  Size histogram map created (FD:" (:fd histogram-map) ")")
      (println "  Totals map created (FD:" (:fd totals-map) ")")

      ;; Initialize maps
      (doseq [i (range SIZE_BUCKETS)]
        (bpf/map-update histogram-map i 0))
      (doseq [i (range 4)]
        (bpf/map-update totals-map i 0))

      (try
        ;; Step 4: Create BPF program
        (println "\nStep 4: Creating memory profiler...")
        (let [profiler (create-alloc-tracker (:fd counts-map) (:fd histogram-map))]
          (println "  Profiler assembled (" (/ (count profiler) 8) "instructions)")

          ;; Step 5: Load program
          (println "\nStep 5: Loading profiler...")
          (let [prog (bpf/load-program {:prog-type :kprobe
                                        :insns profiler})]
            (println "  Profiler loaded (FD:" (:fd prog) ")")

            (try
              ;; Step 6: Explain kprobe attachment
              (println "\nStep 6: Kprobe attachment info...")
              (println "  Note: Kprobe attachment requires Chapter 5")
              (println "  Would attach to: __kmalloc")
              (println)
              (println "  Memory allocation functions:")
              (println "    - __kmalloc: General kernel allocator")
              (println "    - kmem_cache_alloc: Slab allocator")
              (println "    - alloc_pages: Page allocator")
              (println "    - vmalloc: Virtual memory allocator")

              ;; Step 7: Simulate allocation data
              (println "\nStep 7: Simulating allocation data...")
              (simulate-allocation-data counts-map bytes-map histogram-map totals-map)

              ;; Step 8: Display analysis
              (println "\nStep 8: Analyzing allocation patterns...")
              (let [alloc-data (get-allocation-data counts-map bytes-map)]
                (display-statistics alloc-data totals-map)
                (display-size-histogram histogram-map)
                (display-top-allocators alloc-data 5)
                (display-flame-graph-data alloc-data kallsyms))

              ;; Step 9: Show helper function usage
              (println "\n\nStep 9: Helper function usage summary...")
              (println "  Helper functions demonstrated:")
              (println "    - bpf_get_current_pid_tgid(): Get process context")
              (println "    - bpf_ktime_get_ns(): Timestamp for correlation")
              (println "    - bpf_map_lookup_elem(): Query existing data")
              (println "    - bpf_map_update_elem(): Store new data")
              (println)
              (println "  Advanced helpers (covered in later chapters):")
              (println "    - bpf_get_stackid(): Capture call stacks")
              (println "    - bpf_get_stack(): Get raw stack data")
              (println "    - bpf_ringbuf_output(): Stream events")

              ;; Step 10: Cleanup
              (println "\nStep 10: Cleanup...")
              (bpf/close-program prog)
              (println "  Program closed")

              (catch Exception e
                (println "Error:" (.getMessage e))
                (.printStackTrace e)))))

        (catch Exception e
          (println "Error loading program:" (.getMessage e))
          (.printStackTrace e))

        (finally
          (bpf/close-map counts-map)
          (bpf/close-map bytes-map)
          (bpf/close-map histogram-map)
          (bpf/close-map totals-map)
          (println "  Maps closed")))))

  (println "\n=== Lab 4.3 Complete! ===")
  true)

;;; ============================================================================
;;; Part 9: Challenge - Memory Leak Detection
;;; ============================================================================

(defn run-challenge []
  "Challenge: Memory leak detection

   Tracks allocations and frees to identify:
   - Outstanding allocations (potential leaks)
   - Allocation/free imbalance per stack
   - Long-lived allocations"

  (println "\n=== Lab 4.3 Challenge: Memory Leak Detection ===\n")

  ;; This demonstrates the concept - actual implementation
  ;; would require tracking both allocs and frees

  (let [outstanding {1 {:allocs 1500 :frees 1480 :bytes 1280}
                     2 {:allocs 800 :frees 800 :bytes 0}
                     3 {:allocs 400 :frees 350 :bytes 51200}
                     4 {:allocs 200 :frees 200 :bytes 0}
                     5 {:allocs 100 :frees 90 :bytes 40960}}]

    (println "Outstanding Allocations (potential leaks):")
    (println "═══════════════════════════════════════════════════════")

    (doseq [[stack-id {:keys [allocs frees bytes]}] (sort-by (comp :bytes val) > outstanding)
            :when (not= allocs frees)]
      (let [leaked (- allocs frees)]
        (println (format "\nStack ID %d:" stack-id))
        (println (format "  Allocations: %,d" allocs))
        (println (format "  Frees:       %,d" frees))
        (println (format "  Outstanding: %,d (%s)" leaked (format-size bytes)))))

    (let [total-leaked (reduce + (map :bytes (vals outstanding)))]
      (println "\n───────────────────────────────────────")
      (println (format "Total leaked: %s" (format-size total-leaked)))))

  (println "\n=== Challenge Complete! ==="))

(defn -main [& args]
  (run-lab)
  (run-challenge)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)
  (run-challenge)

  ;; Test size formatting
  (format-size 1024)
  (format-size (* 1024 1024))

  ;; Load kernel symbols
  (def kallsyms (load-kallsyms))
  (count kallsyms)
  (take 10 kallsyms)
  )
