(ns macro-dsl
  "High-Level Macro DSL Example

   This example demonstrates using the high-level declarative macros
   to write BPF programs with minimal boilerplate. These macros make
   clj-ebpf feel more 'Clojure-like' for quick scripts and applications.

   Main macros demonstrated:
   - defmap-spec: Define reusable map specifications
   - defprogram: Define BPF programs with assembled bytecode
   - with-bpf-script: Lifecycle management for the complete BPF stack

   Usage:
     sudo clojure -M:examples -m macro-dsl"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.macros :refer [defprogram defmap-spec with-bpf-script]]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; Example 1: Simple Map Specifications
;; ============================================================================

(defmap-spec counter-map
  "A simple array map to store a counter"
  :type :array
  :key-size 4
  :value-size 8
  :max-entries 1)

(defmap-spec event-hash-map
  "A hash map for storing event data"
  :type :hash
  :key-size 4
  :value-size 16
  :max-entries 10000)

(defmap-spec pid-filter-map
  "An LRU hash map for PID filtering"
  :type :lru-hash
  :key-size 4
  :value-size 4
  :max-entries 1024)

(defn demo-map-specs
  "Demonstrate map specification definitions."
  []
  (println "\n=== Map Specifications ===\n")

  (println "counter-map spec:")
  (println "  Type:" (:map-type counter-map))
  (println "  Key size:" (:key-size counter-map))
  (println "  Value size:" (:value-size counter-map))
  (println "  Max entries:" (:max-entries counter-map))
  (println "  Name:" (:map-name counter-map))

  (println "\nevent-hash-map spec:")
  (println "  Type:" (:map-type event-hash-map))
  (println "  Max entries:" (:max-entries event-hash-map))

  (println "\npid-filter-map spec:")
  (println "  Type:" (:map-type pid-filter-map)))

;; ============================================================================
;; Example 2: Simple Program Definitions
;; ============================================================================

;; XDP program that passes all packets
(defprogram xdp-pass-all
  :type :xdp
  :license "GPL"
  :body [(dsl/mov :r0 2)      ; XDP_PASS = 2
         (dsl/exit-insn)])

;; XDP program that drops all packets
(defprogram xdp-drop-all
  :type :xdp
  :license "GPL"
  :body [(dsl/mov :r0 1)      ; XDP_DROP = 1
         (dsl/exit-insn)])

;; Kprobe program (minimal)
(defprogram kprobe-minimal
  :type :kprobe
  :license "GPL"
  :body [(dsl/mov :r0 0)
         (dsl/exit-insn)])

(defn demo-program-definitions
  "Demonstrate program definitions."
  []
  (println "\n=== Program Definitions ===\n")

  (println "xdp-pass-all:")
  (println "  Type:" (:prog-type xdp-pass-all))
  (println "  License:" (:license xdp-pass-all))
  (println "  Name:" (:prog-name xdp-pass-all))

  (println "\nxdp-drop-all:")
  (println "  Type:" (:prog-type xdp-drop-all))

  (println "\nkprobe-minimal:")
  (println "  Type:" (:prog-type kprobe-minimal))

  ;; Show assembled bytecode
  (println "\nAssembled bytecode for xdp-pass-all:")
  (let [bytecode ((:body-fn xdp-pass-all))]
    (println "  Size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))))

;; ============================================================================
;; Example 3: More Complex Programs
;; ============================================================================

;; XDP program with basic logic
(defprogram xdp-with-logic
  :type :xdp
  :license "GPL"
  :opts {:log-level 2}
  :body [;; Save context pointer
         (dsl/mov-reg :r6 :r1)
         ;; Load data pointer (32-bit load from xdp_md)
         (dsl/ldx :w :r2 :r6 0)
         ;; Load data_end pointer (32-bit load from xdp_md)
         (dsl/ldx :w :r3 :r6 4)
         ;; Add offset for Ethernet header (14 bytes)
         (dsl/mov-reg :r4 :r2)
         (dsl/add :r4 14)
         ;; Bounds check: if data + 14 > data_end, pass
         (dsl/jmp-reg :jgt :r4 :r3 2)
         ;; Packet is large enough, pass it
         (dsl/mov :r0 2)        ; XDP_PASS
         (dsl/exit-insn)
         ;; Packet too small, also pass
         (dsl/mov :r0 2)        ; XDP_PASS
         (dsl/exit-insn)])

;; Kprobe with process info
(defprogram kprobe-with-pid
  :type :kprobe
  :license "GPL"
  :body [;; Call get_current_pid_tgid helper
         (dsl/call 14)           ; Helper ID for get_current_pid_tgid
         ;; Result is in r0, save to r6
         (dsl/mov-reg :r6 :r0)
         ;; Return 0
         (dsl/mov :r0 0)
         (dsl/exit-insn)])

(defn demo-complex-programs
  "Demonstrate more complex program definitions."
  []
  (println "\n=== Complex Programs ===\n")

  (println "xdp-with-logic:")
  (let [bytecode ((:body-fn xdp-with-logic))]
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))
    (println "  Log level:" (:log-level xdp-with-logic)))

  (println "\nkprobe-with-pid:")
  (let [bytecode ((:body-fn kprobe-with-pid))]
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))))

;; ============================================================================
;; Example 4: Using with-bpf-script (Requires Root)
;; ============================================================================

(defn demo-with-bpf-script
  "Demonstrate with-bpf-script lifecycle management.
   NOTE: Requires root privileges."
  []
  (println "\n=== with-bpf-script Demo ===\n")
  (println "This demo requires root privileges.")
  (println "Running on loopback interface for safety.\n")

  (try
    (with-bpf-script
      {:maps   [m counter-map]
       :progs  [p xdp-pass-all]
       :attach [{:prog p :type :xdp :target "lo"}]}

      (println "BPF resources created:")
      (println "  Map FD:" (:fd m))
      (println "  Program FD:" (:fd p))
      (println)

      ;; Use the map
      (println "Working with the map:")
      (bpf/map-update m 0 0)
      (println "  Initial value:" (bpf/map-lookup m 0))

      (bpf/map-update m 0 42)
      (println "  After update:" (bpf/map-lookup m 0))

      (bpf/map-update m 0 100)
      (println "  After second update:" (bpf/map-lookup m 0))

      (println)
      (println "XDP program attached to loopback.")
      (println "Sleeping for 2 seconds...")
      (Thread/sleep 2000)

      (println "Final counter value:" (bpf/map-lookup m 0)))

    (println "\nCleanup complete - all resources released.")

    (catch Exception e
      (println "Error (may need sudo):" (.getMessage e)))))

;; ============================================================================
;; Example 5: Multiple Maps and Programs
;; ============================================================================

(defmap-spec multi-counter-map
  :type :array
  :key-size 4
  :value-size 8
  :max-entries 10)

(defmap-spec multi-hash-map
  :type :hash
  :key-size 4
  :value-size 8
  :max-entries 1000)

(defprogram multi-prog-1
  :type :xdp
  :license "GPL"
  :body [(dsl/mov :r0 2)
         (dsl/exit-insn)])

(defprogram multi-prog-2
  :type :kprobe
  :license "GPL"
  :body [(dsl/mov :r0 0)
         (dsl/exit-insn)])

(defn demo-multiple-resources
  "Demonstrate using multiple maps and programs.
   NOTE: Requires root privileges."
  []
  (println "\n=== Multiple Resources Demo ===\n")
  (println "This demo requires root privileges.\n")

  (try
    (with-bpf-script
      {:maps   [counter multi-counter-map
                cache multi-hash-map]
       :progs  [xdp-prog multi-prog-1]
       :attach [{:prog xdp-prog :type :xdp :target "lo"}]}

      (println "Created resources:")
      (println "  counter map FD:" (:fd counter))
      (println "  cache map FD:" (:fd cache))
      (println "  xdp-prog FD:" (:fd xdp-prog))
      (println)

      ;; Work with counter map (array)
      (println "Working with counter (array) map:")
      (doseq [i (range 5)]
        (bpf/map-update counter i (* i 10)))
      (doseq [i (range 5)]
        (println "  counter[" i "] =" (bpf/map-lookup counter i)))
      (println)

      ;; Work with cache map (hash)
      (println "Working with cache (hash) map:")
      (bpf/map-update cache 100 1000)
      (bpf/map-update cache 200 2000)
      (bpf/map-update cache 300 3000)
      (println "  cache[100] =" (bpf/map-lookup cache 100))
      (println "  cache[200] =" (bpf/map-lookup cache 200))
      (println "  cache[300] =" (bpf/map-lookup cache 300))

      (println)
      (println "Sleeping for 1 second...")
      (Thread/sleep 1000))

    (println "\nCleanup complete.")

    (catch Exception e
      (println "Error (may need sudo):" (.getMessage e)))))

;; ============================================================================
;; Example 6: Manual Loading Pattern
;; ============================================================================

(defn demo-manual-loading
  "Demonstrate manual loading without with-bpf-script.
   NOTE: Requires root privileges."
  []
  (println "\n=== Manual Loading Demo ===\n")
  (println "Using load-defprogram and create-defmap functions.\n")

  (try
    ;; Create map manually
    (let [m (bpf/create-defmap counter-map)]
      (try
        (println "Map created with FD:" (:fd m))

        ;; Load program manually
        (let [p (bpf/load-defprogram xdp-pass-all)]
          (try
            (println "Program loaded with FD:" (:fd p))

            ;; Work with resources
            (bpf/map-update m 0 999)
            (println "Map value:" (bpf/map-lookup m 0))

            (finally
              (bpf/close-program p)
              (println "Program closed."))))

        (finally
          (bpf/close-map m)
          (println "Map closed."))))

    (catch Exception e
      (println "Error (may need sudo):" (.getMessage e)))))

;; ============================================================================
;; Example 7: Real-World Pattern - Event Tracing
;; ============================================================================

(defmap-spec event-ringbuf
  :type :ringbuf
  :key-size 0
  :value-size 0
  :max-entries (* 256 1024))  ; 256KB ring buffer

(defmap-spec event-count-map
  :type :percpu-array
  :key-size 4
  :value-size 8
  :max-entries 1)

(defprogram tracing-prog
  :type :kprobe
  :license "GPL"
  :opts {:prog-name "event_tracer"}
  :body [;; Get current PID
         (dsl/call 14)           ; get_current_pid_tgid
         (dsl/mov-reg :r6 :r0)
         ;; Return 0
         (dsl/mov :r0 0)
         (dsl/exit-insn)])

(defn demo-tracing-pattern
  "Demonstrate a real-world event tracing pattern."
  []
  (println "\n=== Event Tracing Pattern ===\n")

  (println "Map and program definitions for event tracing:")
  (println)

  (println "event-ringbuf:")
  (println "  Type:" (:map-type event-ringbuf))
  (println "  Max entries:" (:max-entries event-ringbuf) "bytes")
  (println)

  (println "event-count-map:")
  (println "  Type:" (:map-type event-count-map))
  (println "  Per-CPU: yes")
  (println)

  (println "tracing-prog:")
  (println "  Type:" (:prog-type tracing-prog))
  (println "  Name:" (:prog-name tracing-prog))
  (println "  Body source:" (pr-str (:body-source tracing-prog))))

;; ============================================================================
;; Example 8: Comparing Old vs New Syntax
;; ============================================================================

(defn demo-syntax-comparison
  "Show the syntax improvement from macros."
  []
  (println "\n=== Syntax Comparison ===\n")

  (println "OLD WAY (verbose):")
  (println "```clojure")
  (println "(bpf/with-map [m {:map-type :hash")
  (println "                  :key-size 4")
  (println "                  :value-size 4")
  (println "                  :max-entries 1000")
  (println "                  :map-name \"my_map\"")
  (println "                  :key-serializer utils/int->bytes")
  (println "                  :key-deserializer utils/bytes->int")
  (println "                  :value-serializer utils/int->bytes")
  (println "                  :value-deserializer utils/bytes->int}]")
  (println "  (bpf/with-program [prog {:prog-type :xdp")
  (println "                           :insns (dsl/assemble [(dsl/mov :r0 2)")
  (println "                                                 (dsl/exit-insn)])")
  (println "                           :license \"GPL\"")
  (println "                           :prog-name \"my_prog\"}]")
  (println "    (let [attached (bpf/attach-xdp prog \"lo\" 0 :skb)]")
  (println "      (try")
  (println "        ;; Do work")
  (println "        (finally")
  (println "          (bpf/detach-xdp \"lo\"))))))")
  (println "```")
  (println)

  (println "NEW WAY (with macros):")
  (println "```clojure")
  (println "(defmap-spec my-map")
  (println "  :type :hash")
  (println "  :key-size 4")
  (println "  :value-size 4")
  (println "  :max-entries 1000)")
  (println)
  (println "(defprogram my-prog")
  (println "  :type :xdp")
  (println "  :body [(dsl/mov :r0 2)")
  (println "         (dsl/exit-insn)])")
  (println)
  (println "(with-bpf-script")
  (println "  {:maps [m my-map]")
  (println "   :progs [p my-prog]")
  (println "   :attach [{:prog p :type :xdp :target \"lo\"}]}")
  (println "  ;; Do work")
  (println "  )")
  (println "```")
  (println)

  (println "Benefits:")
  (println "  - 60% less boilerplate")
  (println "  - Automatic resource cleanup")
  (println "  - Reusable specifications")
  (println "  - Declarative style"))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run all macro DSL demonstrations."
  [& args]
  (println "==============================================")
  (println "  High-Level Macro DSL Examples")
  (println "==============================================")

  ;; These demos don't require root
  (demo-map-specs)
  (demo-program-definitions)
  (demo-complex-programs)
  (demo-tracing-pattern)
  (demo-syntax-comparison)

  ;; Check if we should run privileged demos
  (when (some #{"--with-root" "-r"} args)
    (println "\n--- Running privileged demos (requires sudo) ---")
    (demo-with-bpf-script)
    (demo-multiple-resources)
    (demo-manual-loading))

  (println "\n==============================================")
  (println "  Demonstrations Complete!")
  (if (some #{"--with-root" "-r"} args)
    (println "  (All demos including privileged)")
    (println "  (Run with --with-root for privileged demos)"))
  (println "=============================================="))

;; ============================================================================
;; REPL Usage
;; ============================================================================

(comment
  ;; Run all non-privileged demos
  (-main)

  ;; Run including privileged demos (needs sudo)
  (-main "--with-root")

  ;; Inspect map specs
  counter-map
  event-hash-map

  ;; Inspect program specs
  xdp-pass-all
  xdp-drop-all

  ;; Get bytecode
  ((:body-fn xdp-pass-all))

  ;; Manual loading
  (bpf/create-defmap counter-map)
  (bpf/load-defprogram xdp-pass-all)
  )
