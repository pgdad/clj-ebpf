(ns clj-ebpf.macros
  "High-level declarative macros for clj-ebpf.

   This namespace provides macros that reduce boilerplate and make BPF
   programming more 'Clojure-like' for scripting and application development.

   Main macros:
   - `defprogram`    - Define a named BPF program with assembled bytecode
   - `defmap-spec`   - Define a reusable map specification
   - `with-bpf-script` - Lifecycle management for maps, programs, and attachments"
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.xdp :as xdp]
            [clj-ebpf.tc :as tc]
            [clj-ebpf.cgroup :as cgroup]
            [clj-ebpf.lsm :as lsm]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; defmap-spec - Define Reusable Map Specifications
;; ============================================================================

(defmacro defmap-spec
  "Define a reusable BPF map specification.

   Creates a var containing a map specification that can be passed to
   `create-map` or used with `with-bpf-script`.

   Parameters:
     name - The var name for this map specification
     docstring - Optional documentation string

   Options (keyword args):
     :type          - Map type keyword (:hash, :array, :lru-hash, :percpu-hash,
                      :percpu-array, :lru-percpu-hash, :stack, :queue, :ringbuf,
                      :lpm-trie, :perf-event-array)
     :key-size      - Size of key in bytes (required for most map types)
     :value-size    - Size of value in bytes (required for most map types)
     :max-entries   - Maximum number of entries (required)
     :flags         - Optional map flags (default 0)
     :map-name      - Optional name string for the map
     :key-serializer   - Function to serialize keys to bytes (default: int->bytes)
     :key-deserializer - Function to deserialize bytes to keys (default: bytes->int)
     :value-serializer   - Function to serialize values to bytes (default: int->bytes)
     :value-deserializer - Function to deserialize bytes to values (default: bytes->int)

   Example:
     (defmap-spec my-hash-map
       :type :hash
       :key-size 4
       :value-size 8
       :max-entries 1024)

     ;; With docstring:
     (defmap-spec my-hash-map
       \"A map for storing events\"
       :type :hash
       :key-size 4
       :value-size 8
       :max-entries 1024)

     ;; Usage:
     (bpf/with-map [m (bpf/create-map my-hash-map)]
       (bpf/map-update m 1 100))

     ;; Or with with-bpf-script:
     (with-bpf-script {:maps [m my-hash-map]}
       (bpf/map-update m 1 100))"
  [name & args]
  (let [[docstring opts] (if (string? (first args))
                           [(first args) (rest args)]
                           [nil args])
        {:keys [type key-size value-size max-entries flags map-name
                key-serializer key-deserializer
                value-serializer value-deserializer]
         :or {flags 0
              key-serializer `utils/int->bytes
              key-deserializer `utils/bytes->int
              value-serializer `utils/int->bytes
              value-deserializer `utils/bytes->int}} (apply hash-map opts)]
    `(def ~(if docstring
             (vary-meta name assoc :doc docstring)
             name)
       {:map-type ~type
        :key-size ~key-size
        :value-size ~value-size
        :max-entries ~max-entries
        :map-flags ~flags
        :map-name ~(or map-name (str name))
        :key-serializer ~key-serializer
        :key-deserializer ~key-deserializer
        :value-serializer ~value-serializer
        :value-deserializer ~value-deserializer})))

;; ============================================================================
;; defprogram - Define Named BPF Programs
;; ============================================================================

(defmacro defprogram
  "Define a named BPF program with assembled bytecode and metadata.

   Creates a var containing a map with the program specification that can
   be passed to `load-program` or used with `with-bpf-script`.

   Parameters:
     name - The var name for this program
     docstring - Optional documentation string

   Options (keyword args):
     :type        - Program type keyword (:kprobe, :kretprobe, :uprobe, :uretprobe,
                    :tracepoint, :raw-tracepoint, :xdp, :tc, :cgroup-skb,
                    :cgroup-sock, :lsm, :fentry, :fexit, :socket-filter, etc.)
     :license     - License string (default \"GPL\")
     :body        - Vector of DSL instructions (will be assembled into bytecode)
     :opts        - Optional map of additional options:
                    :log-level - Verifier log level (0=off, 1=basic, 2=verbose)
                    :prog-name - Program name for debugging

   The :body is assembled into bytecode using `clj-ebpf.dsl/assemble`.

   Example:
     (defprogram my-xdp-filter
       :type :xdp
       :license \"GPL\"
       :body [(dsl/mov :r0 2)     ; XDP_PASS
              (dsl/exit-insn)])

     ;; With docstring:
     (defprogram my-xdp-filter
       \"An XDP program that passes all packets\"
       :type :xdp
       :body [(dsl/mov :r0 2)
              (dsl/exit-insn)])

     ;; Usage:
     (bpf/with-program [prog (bpf/load-program my-xdp-filter)]
       (bpf/attach-xdp prog \"lo\"))

     ;; Or with with-bpf-script:
     (with-bpf-script {:progs [p my-xdp-filter]
                       :attach [{:prog p :type :xdp :target \"lo\"}]}
       (Thread/sleep 5000))"
  [name & args]
  (let [[docstring opts-list] (if (string? (first args))
                                [(first args) (rest args)]
                                [nil args])
        {:keys [type license body opts]
         :or {license "GPL"
              opts {}}} (apply hash-map opts-list)
        prog-name (or (:prog-name opts) (str name))
        log-level (get opts :log-level 1)]
    `(def ~(if docstring
             (vary-meta name assoc :doc docstring)
             name)
       {:prog-type ~type
        :license ~license
        :prog-name ~prog-name
        :log-level ~log-level
        ;; Assemble body instructions into bytecode at runtime
        ;; This allows the body to reference runtime values (like map FDs)
        :body-fn (fn [] (dsl/assemble (vec (flatten [~@body]))))
        ;; Store the original body for inspection
        :body-source '~body})))

(defn- resolve-program-spec
  "Resolve a program spec to include assembled bytecode.
   Called at runtime when the program is about to be loaded."
  [prog-spec]
  (if-let [body-fn (:body-fn prog-spec)]
    (assoc prog-spec :insns (body-fn))
    prog-spec))

;; ============================================================================
;; with-bpf-script - Lifecycle Management Macro
;; ============================================================================

(defn create-maps-from-specs
  "Create BPF maps from specifications. Returns map of binding->BpfMap."
  [map-specs]
  (reduce
   (fn [acc [binding spec]]
     (assoc acc binding (maps/create-map spec)))
   {}
   (partition 2 map-specs)))

(defn close-maps
  "Close all BPF maps."
  [maps-map]
  (doseq [[_ m] maps-map]
    (try
      (maps/close-map m)
      (catch Exception e
        (println "Warning: failed to close map:" (.getMessage e))))))

(defn load-programs-from-specs
  "Load BPF programs from specifications. Returns map of binding->BpfProgram."
  [prog-specs maps-map]
  (reduce
   (fn [acc [binding spec]]
     (let [resolved-spec (resolve-program-spec spec)
           prog (programs/load-program resolved-spec)]
       (assoc acc binding prog)))
   {}
   (partition 2 prog-specs)))

(defn close-programs
  "Close all BPF programs."
  [progs-map]
  (doseq [[_ prog] progs-map]
    (try
      (programs/close-program prog)
      (catch Exception e
        (println "Warning: failed to close program:" (.getMessage e))))))

(defn perform-attachments
  "Perform attachments based on attach specifications.
   Returns a vector of [prog-binding updated-prog] pairs."
  [attach-specs progs-map]
  (reduce
   (fn [acc attach-spec]
     (let [{:keys [prog type target]} attach-spec
           prog-instance (get progs-map prog)]
       (when-not prog-instance
         (throw (ex-info (str "Program not found: " prog) {:prog prog})))
       (let [attached-prog
             (case type
               :xdp
               (let [{:keys [flags mode]} attach-spec
                     attached (xdp/attach-xdp prog-instance target
                                              (or flags 0)
                                              (or mode :skb))]
                 attached)

               :tc
               (let [{:keys [direction priority]} attach-spec]
                 (tc/setup-tc-ingress
                  (:fd prog-instance)
                  target
                  (or priority 1)))

               :kprobe
               (let [{:keys [function retprobe?]} attach-spec]
                 (programs/attach-kprobe prog-instance
                                         {:function function
                                          :retprobe? (or retprobe? false)}))

               :kretprobe
               (let [{:keys [function]} attach-spec]
                 (programs/attach-kprobe prog-instance
                                         {:function function
                                          :retprobe? true}))

               :tracepoint
               (let [{:keys [category event]} attach-spec]
                 (programs/attach-tracepoint prog-instance
                                             {:category category
                                              :name event}))

               :uprobe
               (let [{:keys [binary offset symbol retprobe?]} attach-spec]
                 (programs/attach-uprobe prog-instance
                                         {:binary binary
                                          :offset offset
                                          :symbol symbol
                                          :retprobe? (or retprobe? false)}))

               :uretprobe
               (let [{:keys [binary offset symbol]} attach-spec]
                 (programs/attach-uprobe prog-instance
                                         {:binary binary
                                          :offset offset
                                          :symbol symbol
                                          :retprobe? true}))

               :cgroup-skb
               (let [{:keys [cgroup-path direction]} attach-spec]
                 (cgroup/attach-cgroup-program
                  prog-instance cgroup-path
                  (if (= direction :egress) :cgroup-skb-egress :cgroup-skb-ingress)))

               :cgroup-sock
               (let [{:keys [cgroup-path]} attach-spec]
                 (cgroup/attach-cgroup-program
                  prog-instance cgroup-path :cgroup-sock))

               :lsm
               (let [{:keys [hook]} attach-spec]
                 (lsm/attach-lsm-program prog-instance hook))

               ;; Default: return program unchanged
               prog-instance)]
         (conj acc [prog attached-prog]))))
   []
   attach-specs))

(defn detach-all
  "Detach all attached programs."
  [attached-pairs]
  (doseq [[_ prog] attached-pairs]
    (try
      (when prog
        ;; Programs with attachments should have them auto-detached on close
        ;; But for XDP we may need explicit detach
        (when-let [attachments (:attachments prog)]
          (doseq [attachment attachments]
            (when (= (:type attachment) :xdp)
              (try
                (xdp/detach-xdp (:interface attachment))
                (catch Exception _))))))
      (catch Exception e
        (println "Warning: failed to detach:" (.getMessage e))))))

(defmacro with-bpf-script
  "Execute body with BPF maps, programs, and attachments, ensuring cleanup.

   This is the 'god macro' for quick scripts, tutorials, and REPL experiments.
   It handles the entire lifecycle of BPF resources.

   Parameters:
     config - Map with the following optional keys:
       :maps   - Vector of [binding map-spec] pairs for maps to create
       :progs  - Vector of [binding prog-spec] pairs for programs to load
       :attach - Vector of attachment specifications
     body   - Forms to execute while resources are active

   Attachment specification keys:
     :prog   - Binding name of the program to attach
     :type   - Attachment type (:xdp, :tc, :kprobe, :kretprobe, :tracepoint,
               :uprobe, :uretprobe, :cgroup-skb, :cgroup-sock, :lsm)
     :target - Target for attachment (interface, function name, cgroup path, etc.)

   Type-specific options:
     :xdp       - :flags, :mode (:skb, :native, :offload)
     :tc        - :direction (:ingress, :egress), :priority
     :kprobe    - :function, :retprobe?
     :tracepoint - :category, :event
     :uprobe    - :binary, :offset, :symbol, :retprobe?
     :cgroup-skb - :cgroup-path, :direction (:ingress, :egress)
     :cgroup-sock - :cgroup-path
     :lsm       - :hook

   Example:
     (defmap-spec counter-map
       :type :array
       :key-size 4
       :value-size 8
       :max-entries 1)

     (defprogram filter-prog
       :type :xdp
       :body [(dsl/mov :r0 2)  ; XDP_PASS
              (dsl/exit-insn)])

     (with-bpf-script
       {:maps   [m counter-map]
        :progs  [p filter-prog]
        :attach [{:prog p :type :xdp :target \"lo\"}]}

       (println \"BPF running on loopback\")
       (bpf/map-update m 0 42)
       (println \"Counter:\" (bpf/map-lookup m 0))
       (Thread/sleep 5000))
     ;; Automatically detaches, unloads programs, and closes maps"
  [{:keys [maps progs attach]} & body]
  (let [map-pairs (partition 2 maps)
        map-bindings (mapv first map-pairs)
        prog-pairs (partition 2 progs)
        prog-bindings (mapv first prog-pairs)
        maps-sym (gensym "maps-map")
        progs-sym (gensym "progs-map")
        attached-sym (gensym "attached-pairs")]
    ;; Build the let bindings for maps - quote the binding names as keys
    `(let [~maps-sym (create-maps-from-specs
                       ~(vec (mapcat (fn [[b s]] [(list 'quote b) s]) map-pairs)))
           ~@(mapcat (fn [b] [b `(get ~maps-sym (quote ~b))]) map-bindings)]
       (try
         (let [~progs-sym (load-programs-from-specs
                            ~(vec (mapcat (fn [[b s]] [(list 'quote b) s]) prog-pairs))
                            ~maps-sym)
               ~@(mapcat (fn [b] [b `(get ~progs-sym (quote ~b))]) prog-bindings)]
           (try
             (let [~attached-sym (perform-attachments
                                   ~(vec attach)
                                   ~progs-sym)]
               (try
                 ~@body
                 (finally
                   (detach-all ~attached-sym))))
             (finally
               (close-programs ~progs-sym))))
         (finally
           (close-maps ~maps-sym))))))

;; ============================================================================
;; Convenience Functions
;; ============================================================================

(defn load-defprogram
  "Load a program defined with defprogram.

   This is a convenience function that resolves the program spec and loads it.

   Parameters:
     prog-spec - A program specification created with defprogram

   Returns:
     A loaded BpfProgram record

   Example:
     (defprogram my-prog :type :xdp :body [...])
     (let [prog (load-defprogram my-prog)]
       (try
         ;; use prog
         (finally
           (bpf/close-program prog))))"
  [prog-spec]
  (programs/load-program (resolve-program-spec prog-spec)))

(defn create-defmap
  "Create a map from a specification defined with defmap-spec.

   This is a convenience function that creates a BPF map from a spec.

   Parameters:
     map-spec - A map specification created with defmap-spec

   Returns:
     A BpfMap record

   Example:
     (defmap-spec my-map :type :hash :key-size 4 :value-size 4 :max-entries 100)
     (let [m (create-defmap my-map)]
       (try
         ;; use map
         (finally
           (bpf/close-map m))))"
  [map-spec]
  (maps/create-map map-spec))
