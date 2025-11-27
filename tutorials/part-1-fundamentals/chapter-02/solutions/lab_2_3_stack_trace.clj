(ns lab-2-3-stack-trace
  "Lab 2.3: Stack Trace Collector using BPF stack trace maps

   This solution demonstrates:
   - Creating stack trace maps
   - Combining hash maps with stack trace maps
   - Kernel symbol resolution from /proc/kallsyms
   - Profiling data visualization

   Run with: clojure -M -m lab-2-3-stack-trace
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str]
            [clojure.java.io :as io])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Configuration
;;; ============================================================================

(def max-stack-depth 127)  ; Maximum depth for stack traces
(def max-stacks 10000)     ; Maximum unique stacks to store

;;; ============================================================================
;;; Part 2: Map Creation
;;; ============================================================================

(defn create-stack-trace-map
  "Create map to store arrays of instruction pointers.
   Key: u32 (stack ID), Value: array of u64 IPs
   Note: Using hash map instead of stack-trace type for demonstration,
   as stack-trace maps can only be populated by kernel via bpf_get_stackid."
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4                        ; u32 for stack ID
                   :value-size (* 8 max-stack-depth)  ; Array of u64 IPs
                   :max-entries max-stacks
                   :map-name "stack_traces"}))

(defn create-counts-map
  "Create hash map to count stack occurrences.
   Key: u32 (stack ID), Value: u64 (count)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 8
                   :max-entries max-stacks
                   :map-name "stack_counts"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 3: BPF Program
;;; ============================================================================

(defn create-profiler-program
  "Create a simple BPF program.
   Note: Actual stack trace capture uses bpf_get_stackid helper."
  [stack-map-fd counts-map-fd]
  (bpf/assemble
    [(bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 4: Kernel Symbol Resolution
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
      (println "Warning: Could not load /proc/kallsyms:" (.getMessage e))
      (println "  Run with sudo to access kernel symbols")
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
;;; Part 5: Data Reading
;;; ============================================================================

(defn read-stack-trace
  "Read stack trace IPs for given stack ID from raw bytes."
  [stack-map stack-id]
  (let [key-bytes (utils/int->bytes stack-id)
        value (bpf/map-lookup stack-map key-bytes)]
    (when value
      (let [bb (if (instance? (Class/forName "[B") value)
                 (ByteBuffer/wrap value)
                 value)]
        (.order bb ByteOrder/LITTLE_ENDIAN)
        (into []
              (for [i (range (quot (.remaining bb) 8))
                    :let [ip (.getLong bb (* i 8))]
                    :when (not= ip 0)]  ; 0 indicates end of stack
                ip))))))

(defn read-stack-counts
  "Read all stack IDs and their counts from the counts map using native map iteration"
  [counts-map]
  (into {} (bpf/map-entries counts-map)))

;;; ============================================================================
;;; Part 6: Visualization
;;; ============================================================================

(defn format-stack-trace
  "Format stack trace with resolved symbols."
  [ips kallsyms]
  (mapv #(resolve-kernel-symbol % kallsyms) ips))

(defn display-stack-trace
  "Display a single stack trace with count."
  [stack-id ips count kallsyms]
  (println (format "\nStack ID %d (%d samples):" stack-id count))
  (println (apply str (repeat 50 "=")))
  (let [symbols (format-stack-trace ips kallsyms)]
    (doseq [[depth sym] (map-indexed vector symbols)]
      (println (format "  %2d: %s" depth sym)))))

(defn display-top-stacks
  "Display top N stack traces by count."
  [stack-map counts-map kallsyms n]
  (let [counts (read-stack-counts counts-map)
        sorted (take n (sort-by val > counts))]

    (println (format "\n\nTop %d Stack Traces:" n))
    (println (apply str (repeat 55 "=")))

    (if (empty? sorted)
      (println "No stack traces captured")
      (doseq [[stack-id count] sorted]
        (let [ips (read-stack-trace stack-map stack-id)]
          (if ips
            (display-stack-trace stack-id ips count kallsyms)
            (println (format "\nStack ID %d (%d samples): <no data>" stack-id count))))))))

(defn display-summary
  "Display summary statistics."
  [counts-map]
  (let [counts (vals (read-stack-counts counts-map))
        total (reduce + 0 counts)
        unique (count counts)]
    (println "\nSummary:")
    (println (apply str (repeat 45 "-")))
    (println "Total samples     :" total)
    (println "Unique stacks     :" unique)
    (println "Avg samples/stack :" (if (pos? unique)
                                     (format "%.1f" (double (/ total unique)))
                                     "N/A"))))

;;; ============================================================================
;;; Part 7: Simulation
;;; ============================================================================

(defn simulate-stack-traces
  "Simulate stack trace captures for testing."
  [stack-map counts-map kallsyms]
  (println "\nSimulating stack trace captures...")

  ;; Create some synthetic stacks using real kernel addresses if available
  (let [;; Try to use real kernel addresses from kallsyms
        sample-addrs (if (seq kallsyms)
                       (->> kallsyms
                            (filter #(= "T" (:type %)))  ; Text (code) symbols
                            (take 20)
                            (mapv :address))
                       ;; Fallback to synthetic addresses (using signed range)
                       [0x7fff81000100
                        0x7fff81000200
                        0x7fff81000300
                        0x7fff81000400
                        0x7fff81000500])

        ;; Create test stacks with varying depths
        test-stacks [(take 3 sample-addrs)
                     (take 4 (drop 1 sample-addrs))
                     (take 2 (drop 3 sample-addrs))
                     (take 5 (drop 2 sample-addrs))]]

    ;; Simulate samples with different frequencies
    (doseq [[stack-id stack] (map-indexed vector test-stacks)]
      (let [sample-count (* (inc stack-id) 10)]  ; 10, 20, 30, 40 samples

        ;; Store stack trace
        (let [stack-key (utils/int->bytes stack-id)
              stack-bb (ByteBuffer/allocate (* 8 max-stack-depth))]
          (.order stack-bb ByteOrder/LITTLE_ENDIAN)
          (doseq [[idx ip] (map-indexed vector stack)]
            (.putLong stack-bb (* idx 8) ip))
          (.position stack-bb 0)
          (bpf/map-update stack-map stack-key (.array stack-bb)))

        ;; Update count
        (bpf/map-update counts-map stack-id sample-count))))

  (println "  Created 4 unique stacks with 10, 20, 30, 40 samples"))

;;; ============================================================================
;;; Part 8: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 2.3: Stack Trace Collector ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Load kernel symbols
  (println "\nStep 2: Loading kernel symbols...")
  (let [kallsyms (load-kallsyms)]
    (println "  Loaded" (count kallsyms) "kernel symbols")

    ;; Step 3: Create maps
    (println "\nStep 3: Creating maps...")
    (let [stack-map (create-stack-trace-map)
          counts-map (create-counts-map)]
      (println "  Stack trace map created (FD:" (:fd stack-map) ")")
      (println "  Counts map created (FD:" (:fd counts-map) ")")
      (println "  Max stack depth:" max-stack-depth)
      (println "  Max stacks:" max-stacks)

      (try
        ;; Step 4: Create profiler program
        (println "\nStep 4: Creating profiler program...")
        (let [program (create-profiler-program (:fd stack-map) (:fd counts-map))]
          (println "  Program assembled (" (/ (count program) 8) "instructions)")

          (println "\nStep 5: Loading program into kernel...")
          (let [prog (bpf/load-program {:prog-type :kprobe :insns program})]
            (println "  Program loaded (FD:" (:fd prog) ")")

            ;; Step 6: Simulate stack traces
            (println "\nStep 6: Kprobe attachment...")
            (println "  Note: Kernel probe attachment requires additional setup")
            (println "  Demonstrating with simulated stack traces...")
            (simulate-stack-traces stack-map counts-map kallsyms)

            ;; Step 7: Display results
            (println "\nStep 7: Analyzing stack traces...")
            (display-summary counts-map)
            (display-top-stacks stack-map counts-map kallsyms 5)

            ;; Step 8: Test individual stack lookup
            (println "\n\nStep 8: Testing individual stack lookup...")
            (let [test-stack-id 2
                  ips (read-stack-trace stack-map test-stack-id)
                  cnts (read-stack-counts counts-map)
                  cnt (get cnts test-stack-id 0)]
              (if ips
                (do
                  (println "  Found stack" test-stack-id)
                  (display-stack-trace test-stack-id ips cnt kallsyms))
                (println "  Stack" test-stack-id "not found")))

            ;; Step 9: Show symbol resolution examples
            (println "\n\nStep 9: Symbol resolution examples...")
            (if (seq kallsyms)
              (do
                (println "  Sample resolved symbols:")
                (doseq [sym (take 5 kallsyms)]
                  (println (format "    0x%x -> %s" (:address sym) (:symbol sym)))))
              (println "  No kernel symbols available (run with sudo)"))

            ;; Cleanup
            (println "\n\nStep 10: Cleanup...")
            (bpf/close-program prog)
            (println "  Program closed")))

        (catch Exception e
          (println "Error:" (.getMessage e))
          (.printStackTrace e))

        (finally
          (bpf/close-map stack-map)
          (bpf/close-map counts-map)
          (println "  Maps closed")))))

  (println "\n=== Lab 2.3 Complete! ===")
  true)

;;; ============================================================================
;;; Part 9: Challenge - Flame Graph Generation
;;; ============================================================================

(defn generate-folded-stacks
  "Generate flame graph data in folded format."
  [stack-map counts-map kallsyms]
  (let [counts (read-stack-counts counts-map)]
    (for [[stack-id count] counts
          :let [ips (read-stack-trace stack-map stack-id)]
          :when ips]
      (let [symbols (format-stack-trace ips kallsyms)
            ;; Reverse for flame graph (deepest first)
            folded (str/join ";" (reverse symbols))]
        {:folded folded :count count}))))

(defn run-challenge []
  (println "\n=== Lab 2.3 Challenge: Flame Graph Generation ===\n")

  ;; Create maps
  (let [stack-map (create-stack-trace-map)
        counts-map (create-counts-map)
        kallsyms (load-kallsyms)]

    (println "Generating sample profiling data...")

    ;; Simulate more diverse stack traces
    (let [sample-addrs (if (seq kallsyms)
                         (->> kallsyms
                              (filter #(= "T" (:type %)))
                              (take 30)
                              (mapv :address))
                         (vec (for [i (range 30)]
                                (+ 0x7fff81000000 (* i 0x100)))))]

      ;; Create 10 different call paths
      (doseq [stack-id (range 10)]
        (let [depth (+ 2 (rand-int 6))  ; 2-7 deep
              start (rand-int 20)
              stack (take depth (drop start sample-addrs))
              sample-count (+ 5 (rand-int 50))]

          ;; Store stack
          (let [stack-key (utils/int->bytes stack-id)
                stack-bb (ByteBuffer/allocate (* 8 max-stack-depth))]
            (.order stack-bb ByteOrder/LITTLE_ENDIAN)
            (doseq [[idx ip] (map-indexed vector stack)]
              (.putLong stack-bb (* idx 8) ip))
            (.position stack-bb 0)
            (bpf/map-update stack-map stack-key (.array stack-bb)))

          ;; Store count
          (bpf/map-update counts-map stack-id sample-count))))

    (println "Created 10 sample stacks")

    ;; Generate folded format
    (println "\nFolded stack format (for flame graphs):")
    (println (apply str (repeat 55 "-")))
    (let [folded (generate-folded-stacks stack-map counts-map kallsyms)]
      (doseq [{:keys [folded count]} (take 5 folded)]
        (println (format "%s %d" folded count)))
      (when (> (count folded) 5)
        (println "...")))

    (println "\nTo generate a flame graph:")
    (println "1. Save folded output to a file")
    (println "2. Run: cat stacks.txt | flamegraph.pl > flame.svg")
    (println "3. Open flame.svg in a browser")

    ;; Cleanup
    (bpf/close-map stack-map)
    (bpf/close-map counts-map)
    (println "\nChallenge maps closed"))

  (println "\n=== Challenge Complete! ==="))

(defn -main [& args]
  (run-lab)
  (run-challenge)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)
  (run-challenge)

  ;; Load and explore kernel symbols
  (def kallsyms (load-kallsyms))
  (count kallsyms)
  (take 10 kallsyms)

  ;; Find specific functions
  (filter #(str/includes? (:symbol %) "do_sys") kallsyms)

  ;; Resolve an address
  (resolve-kernel-symbol 0xffffffff81000100 kallsyms)
  )
