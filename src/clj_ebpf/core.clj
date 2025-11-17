(ns clj-ebpf.core
  "Main API for clj-ebpf - eBPF programming in Clojure"
  (:require [clj-ebpf.constants :as const]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.events :as events]
            [clj-ebpf.xdp :as xdp]
            [clj-ebpf.tc :as tc]
            [clj-ebpf.cgroup :as cgroup]
            [clj-ebpf.elf :as elf]))

;; Re-export main APIs

;; Constants
(def bpf-cmd const/bpf-cmd)
(def map-type const/map-type)
(def prog-type const/prog-type)
(def attach-type const/attach-type)

;; Maps
(def create-map maps/create-map)
(def close-map maps/close-map)
(def map-lookup maps/map-lookup)
(def map-update maps/map-update)
(def map-delete maps/map-delete)
(def map-keys maps/map-keys)
(def map-entries maps/map-entries)
(def map-values maps/map-values)
(def map-count maps/map-count)
(def map-clear maps/map-clear)
(def pin-map maps/pin-map)
(def get-pinned-map maps/get-pinned-map)
(def dump-map maps/dump-map)

;; Convenience map constructors
(def create-hash-map maps/create-hash-map)
(def create-array-map maps/create-array-map)
(def create-lru-hash-map maps/create-lru-hash-map)
(def create-percpu-hash-map maps/create-percpu-hash-map)
(def create-percpu-array-map maps/create-percpu-array-map)
(def create-lru-percpu-hash-map maps/create-lru-percpu-hash-map)
(def create-stack-map maps/create-stack-map)
(def create-queue-map maps/create-queue-map)
(def create-lpm-trie-map maps/create-lpm-trie-map)
(def create-ringbuf-map maps/create-ringbuf-map)

;; Stack/Queue operations
(def stack-push maps/stack-push)
(def stack-pop maps/stack-pop)
(def stack-peek maps/stack-peek)
(def queue-push maps/queue-push)
(def queue-pop maps/queue-pop)
(def queue-peek maps/queue-peek)

;; Batch map operations
(def map-lookup-batch maps/map-lookup-batch)
(def map-update-batch maps/map-update-batch)
(def map-delete-batch maps/map-delete-batch)
(def map-lookup-and-delete-batch maps/map-lookup-and-delete-batch)

;; Per-CPU aggregation helpers
(def percpu-sum maps/percpu-sum)
(def percpu-max maps/percpu-max)
(def percpu-min maps/percpu-min)
(def percpu-avg maps/percpu-avg)

;; Programs
(def load-program programs/load-program)
(def close-program programs/close-program)
(def attach-kprobe programs/attach-kprobe)
(def attach-kretprobe programs/attach-kretprobe)
(def attach-tracepoint programs/attach-tracepoint)
(def attach-raw-tracepoint programs/attach-raw-tracepoint)
(def pin-program programs/pin-program)
(def get-pinned-program programs/get-pinned-program)

;; Events
(def create-ringbuf-consumer events/create-ringbuf-consumer)
(def start-ringbuf-consumer events/start-ringbuf-consumer)
(def stop-ringbuf-consumer events/stop-ringbuf-consumer)
(def get-consumer-stats events/get-consumer-stats)
(def process-events events/process-events)
(def peek-ringbuf-events events/peek-ringbuf-events)
(def make-event-parser events/make-event-parser)
(def make-event-serializer events/make-event-serializer)
(def make-event-handler events/make-event-handler)

;; Utils
(def check-bpf-available utils/check-bpf-available)
(def get-kernel-version utils/get-kernel-version)
(def get-cpu-count utils/get-cpu-count)
(def bpf-fs-mounted? utils/bpf-fs-mounted?)
(def ensure-bpf-fs utils/ensure-bpf-fs)

;; XDP (eXpress Data Path)
(def interface-name->index xdp/interface-name->index)
(def interface-index->name xdp/interface-index->name)
(def attach-xdp xdp/attach-xdp)
(def detach-xdp xdp/detach-xdp)
(def load-xdp-program xdp/load-xdp-program)

;; TC (Traffic Control)
(def tc-action tc/tc-action)
(def add-clsact-qdisc tc/add-clsact-qdisc)
(def remove-clsact-qdisc tc/remove-clsact-qdisc)
(def attach-tc-filter tc/attach-tc-filter)
(def detach-tc-filter tc/detach-tc-filter)
(def load-tc-program tc/load-tc-program)
(def setup-tc-ingress tc/setup-tc-ingress)
(def setup-tc-egress tc/setup-tc-egress)
(def teardown-tc-filter tc/teardown-tc-filter)

;; Cgroup (Control Groups)
(def get-cgroup-fd cgroup/get-cgroup-fd)
(def close-cgroup cgroup/close-cgroup)
(def cgroup-exists? cgroup/cgroup-exists?)
(def attach-cgroup-program cgroup/attach-cgroup-program)
(def detach-cgroup-program cgroup/detach-cgroup-program)
(def load-cgroup-skb-program cgroup/load-cgroup-skb-program)
(def load-cgroup-sock-program cgroup/load-cgroup-sock-program)
(def load-cgroup-device-program cgroup/load-cgroup-device-program)
(def load-cgroup-sysctl-program cgroup/load-cgroup-sysctl-program)
(def setup-cgroup-skb cgroup/setup-cgroup-skb)
(def setup-cgroup-sock cgroup/setup-cgroup-sock)
(def setup-cgroup-device cgroup/setup-cgroup-device)
(def teardown-cgroup-program cgroup/teardown-cgroup-program)
(def get-current-cgroup cgroup/get-current-cgroup)
(def list-cgroup-children cgroup/list-cgroup-children)

;; ELF (Executable and Linkable Format)
(def parse-elf-file elf/parse-elf-file)
(def inspect-elf elf/inspect-elf)
(def load-program-from-elf elf/load-program-from-elf)
(def create-maps-from-elf elf/create-maps-from-elf)
(def load-elf-program-and-maps elf/load-elf-program-and-maps)
(def list-programs elf/list-programs)
(def list-maps elf/list-maps)
(def get-program elf/get-program)
(def get-map-def elf/get-map-def)

;; Macros
(defmacro with-map
  "Create a map and ensure it's closed after use"
  [& args]
  `(maps/with-map ~@args))

(defmacro with-program
  "Load a program and ensure it's closed after use"
  [& args]
  `(programs/with-program ~@args))

(defmacro with-ringbuf-consumer
  "Create and manage a ring buffer consumer"
  [& args]
  `(events/with-ringbuf-consumer ~@args))

(defmacro with-xdp
  "Attach XDP program to interface and ensure detachment after use"
  [& args]
  `(xdp/with-xdp ~@args))

(defmacro with-tc-filter
  "Attach TC filter and ensure detachment after use"
  [& args]
  `(tc/with-tc-filter ~@args))

(defmacro with-tc-program
  "Load TC program, attach filter, and ensure cleanup"
  [& args]
  `(tc/with-tc-program ~@args))

(defmacro with-cgroup-program
  "Attach cgroup program and ensure detachment after use"
  [& args]
  `(cgroup/with-cgroup-program ~@args))

(defmacro with-cgroup-skb
  "Load and attach cgroup SKB program, ensure cleanup"
  [& args]
  `(cgroup/with-cgroup-skb ~@args))

;; Initialization and system check

(defn init!
  "Initialize clj-ebpf and check system compatibility"
  []
  (let [checks (utils/check-bpf-available)]
    (println "clj-ebpf initialized")
    (println "Kernel version:" (format "0x%06x" (:kernel-version checks)))
    (println "BPF filesystem:" (if (:bpf-fs-mounted checks) "mounted" "NOT MOUNTED"))
    (when (:bpf-fs-path checks)
      (println "BPF FS path:" (:bpf-fs-path checks)))
    (println "CAP_BPF:" (if (:has-cap-bpf checks) "yes" "no (may need sudo)"))
    checks))

(defn version
  "Get clj-ebpf version"
  []
  "0.1.0-SNAPSHOT")

;; Example helper for quick testing

(defn run-example
  "Run a simple example to verify clj-ebpf is working"
  []
  (println "\nRunning clj-ebpf example...")
  (println "Creating a hash map...")
  (with-map [test-map {:map-type :hash
                       :key-size 4
                       :value-size 4
                       :max-entries 10
                       :map-name "test_map"
                       :key-serializer utils/int->bytes
                       :key-deserializer utils/bytes->int
                       :value-serializer utils/int->bytes
                       :value-deserializer utils/bytes->int}]
    (println "Map created with FD:" (:fd test-map))

    (println "Inserting values...")
    (map-update test-map 1 100)
    (map-update test-map 2 200)
    (map-update test-map 3 300)

    (println "Looking up values...")
    (println "Key 1 =" (map-lookup test-map 1))
    (println "Key 2 =" (map-lookup test-map 2))
    (println "Key 3 =" (map-lookup test-map 3))

    (println "Iterating over all entries...")
    (doseq [[k v] (map-entries test-map)]
      (println "  " k "=>" v))

    (println "Deleting key 2...")
    (map-delete test-map 2)

    (println "Remaining entries:")
    (doseq [[k v] (map-entries test-map)]
      (println "  " k "=>" v))

    (println "Example completed successfully!")))
