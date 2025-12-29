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
            [clj-ebpf.perf :as perf]
            [clj-ebpf.lsm :as lsm]
            [clj-ebpf.btf :as btf]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.relocate :as relocate]
            [clj-ebpf.elf :as elf]
            [clj-ebpf.helpers :as helpers]
            [clj-ebpf.refs :as refs]
            [clj-ebpf.macros :as macros]))

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

;; Deref-able References (for @ reader macro)
;; Ring buffer refs - blocking reads with @ref
(def ringbuf-ref refs/ringbuf-ref)
(def ringbuf-seq refs/ringbuf-seq)
;; Queue/Stack refs - blocking pop with @ref
(def queue-ref refs/queue-ref)
(def stack-ref refs/stack-ref)
(def queue-seq refs/queue-seq)
;; Map watchers - wait for key with @ref
(def map-watch refs/map-watch)
(def map-watch-changes refs/map-watch-changes)

;; Writable References (for reset!, swap!, conj!)
;; Map entry refs - atom-like access to map entries
(def map-entry-ref refs/map-entry-ref)
;; Queue/Stack writers - conj! to push values
(def queue-writer refs/queue-writer)
(def stack-writer refs/stack-writer)
;; Bidirectional channels - both conj! and blocking deref
(def queue-channel refs/queue-channel)
(def stack-channel refs/stack-channel)

;; Utils
(def check-bpf-available utils/check-bpf-available)
(def get-kernel-version utils/get-kernel-version)
(def get-cpu-count utils/get-cpu-count)
(def bpf-fs-mounted? utils/bpf-fs-mounted?)
(def ensure-bpf-fs utils/ensure-bpf-fs)

;; Architecture detection
(def get-arch utils/get-arch)
(def arch-name utils/arch-name)
(def amd64? utils/amd64?)
(def arm64? utils/arm64?)
(def arm32? utils/arm32?)
(def pointer-size utils/pointer-size)
(def arch-info utils/arch-info)
(def print-arch-info utils/print-arch-info)

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

;; Perf Event Buffers
(def perf-event-open perf/perf-event-open)
(def create-perf-event-array perf/create-perf-event-array)
(def create-perf-consumer perf/create-perf-consumer)
(def start-perf-consumer perf/start-perf-consumer)
(def stop-perf-consumer perf/stop-perf-consumer)
(def get-perf-stats perf/get-perf-stats)
(def read-perf-events perf/read-perf-events)

;; LSM (Linux Security Modules) Hooks
(def load-lsm-program lsm/load-lsm-program)
(def create-lsm-link lsm/create-lsm-link)
(def close-lsm-link lsm/close-lsm-link)
(def attach-lsm-program lsm/attach-lsm-program)
(def detach-lsm-program lsm/detach-lsm-program)
(def setup-lsm-hook lsm/setup-lsm-hook)
(def teardown-lsm-hook lsm/teardown-lsm-hook)
(def lsm-available? lsm/lsm-available?)
(def list-lsm-hooks lsm/list-lsm-hooks)
(def get-lsm-hook-name lsm/get-lsm-hook-name)
(def list-hooks-by-category lsm/list-hooks-by-category)
(def get-hook-category lsm/get-hook-category)

;; BTF (BPF Type Format)
(def load-btf-file btf/load-btf-file)
(def btf-available? btf/btf-available?)
(def get-type-by-id btf/get-type-by-id)
(def get-type-name btf/get-type-name)
(def find-type-by-name btf/find-type-by-name)
(def get-struct-members btf/get-struct-members)
(def get-enum-values btf/get-enum-values)
(def get-func-params btf/get-func-params)
(def resolve-type btf/resolve-type)
(def get-type-size btf/get-type-size)
(def list-types btf/list-types)
(def find-function btf/find-function)
(def get-function-signature btf/get-function-signature)

;; BPF DSL (Domain-Specific Language)
;; Constants
(def registers dsl/registers)
(def xdp-action dsl/xdp-action)
(def tc-action dsl/tc-action)
(def bpf-helpers dsl/bpf-helpers)

;; ALU operations
(def mov dsl/mov)
(def mov-reg dsl/mov-reg)
(def add dsl/add)
(def add-reg dsl/add-reg)
(def sub dsl/sub)
(def sub-reg dsl/sub-reg)
(def mul dsl/mul)
(def mul-reg dsl/mul-reg)
(def div dsl/div)
(def div-reg dsl/div-reg)
(def mod dsl/mod)
(def mod-reg dsl/mod-reg)
(def and-op dsl/and-op)
(def and-reg dsl/and-reg)
(def or-op dsl/or-op)
(def or-reg dsl/or-reg)
(def xor-op dsl/xor-op)
(def xor-reg dsl/xor-reg)
(def lsh dsl/lsh)
(def lsh-reg dsl/lsh-reg)
(def rsh dsl/rsh)
(def rsh-reg dsl/rsh-reg)
(def arsh dsl/arsh)
(def neg-reg dsl/neg-reg)
(def end-to-be dsl/end-to-be)
(def end-to-le dsl/end-to-le)

;; Jump operations
(def ja dsl/ja)
(def jmp-imm dsl/jmp-imm)
(def jmp-reg dsl/jmp-reg)
(def call dsl/call)
(def exit-insn dsl/exit-insn)

;; Load/store operations
(def ldx dsl/ldx)
(def stx dsl/stx)
(def st dsl/st)
(def lddw dsl/lddw)

;; Tutorial-compatible aliases
(def load-mem dsl/load-mem)
(def store-mem dsl/store-mem)
(def ld-map-fd dsl/ld-map-fd)
(def jmp dsl/jmp)
(def exit dsl/exit)
(def load-ctx dsl/load-ctx)
(def map-ref dsl/map-ref)
(def bpf-and dsl/and)
(def endian-be dsl/endian-be)
(def endian-le dsl/endian-le)

;; Assembly
(def assemble dsl/assemble)
(def compile-program dsl/compile-program)

;; CO-RE (Compile Once - Run Everywhere) helpers
(def core-field-offset dsl/core-field-offset)
(def core-field-exists dsl/core-field-exists)
(def core-field-size dsl/core-field-size)
(def core-type-exists dsl/core-type-exists)
(def core-type-size dsl/core-type-size)
(def core-enum-value dsl/core-enum-value)
(def generate-core-read dsl/generate-core-read)

;; CO-RE relocation processing
(def relocation-kind relocate/relocation-kind)
(def create-relocation relocate/create-relocation)
(def apply-relocation relocate/apply-relocation)
(def apply-relocations relocate/apply-relocations)
(def core-read-supported? relocate/core-read-supported?)
(def get-kernel-btf relocate/get-kernel-btf)

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

;; BPF Helper Functions
;; Helper metadata and queries
(def helper-metadata helpers/helper-metadata)
(def get-helper-info helpers/get-helper-info)
(def get-helper-id helpers/get-helper-id)
(def helpers-by-category helpers/helpers-by-category)
(def list-categories helpers/list-categories)
(def available-helpers helpers/available-helpers)
(def helper-compatible? helpers/helper-compatible?)
(def print-helper-info helpers/print-helper-info)
(def list-helpers helpers/list-helpers)

;; Map helpers
(def helper-map-lookup-elem dsl/helper-map-lookup-elem)
(def helper-map-update-elem dsl/helper-map-update-elem)
(def helper-map-delete-elem dsl/helper-map-delete-elem)

;; Probe/trace helpers
(def helper-probe-read dsl/helper-probe-read)
(def helper-probe-read-kernel dsl/helper-probe-read-kernel)
(def helper-probe-read-user dsl/helper-probe-read-user)
(def helper-probe-read-str dsl/helper-probe-read-str)
(def helper-probe-read-kernel-str dsl/helper-probe-read-kernel-str)
(def helper-probe-read-user-str dsl/helper-probe-read-user-str)

;; Time helpers
(def helper-ktime-get-ns dsl/helper-ktime-get-ns)
(def helper-ktime-get-boot-ns dsl/helper-ktime-get-boot-ns)
(def helper-jiffies64 dsl/helper-jiffies64)
(def helper-ktime-get-coarse-ns dsl/helper-ktime-get-coarse-ns)
(def helper-ktime-get-tai-ns dsl/helper-ktime-get-tai-ns)

;; Process information helpers
(def helper-get-current-pid-tgid dsl/helper-get-current-pid-tgid)
(def helper-get-current-uid-gid dsl/helper-get-current-uid-gid)
(def helper-get-current-comm dsl/helper-get-current-comm)
(def helper-get-current-task dsl/helper-get-current-task)
(def helper-get-current-task-btf dsl/helper-get-current-task-btf)

;; CPU/system information helpers
(def helper-get-smp-processor-id dsl/helper-get-smp-processor-id)
(def helper-get-numa-node-id dsl/helper-get-numa-node-id)
(def helper-get-prandom-u32 dsl/helper-get-prandom-u32)

;; Stack trace helpers
(def helper-get-stackid dsl/helper-get-stackid)
(def helper-get-stack dsl/helper-get-stack)
(def helper-get-task-stack dsl/helper-get-task-stack)

;; Perf event helpers
(def helper-perf-event-output dsl/helper-perf-event-output)
(def helper-perf-event-read dsl/helper-perf-event-read)

;; Ring buffer helpers
(def helper-ringbuf-output dsl/helper-ringbuf-output)
(def helper-ringbuf-reserve dsl/helper-ringbuf-reserve)
(def helper-ringbuf-submit dsl/helper-ringbuf-submit)
(def helper-ringbuf-discard dsl/helper-ringbuf-discard)

;; Debug helpers
(def helper-trace-printk dsl/helper-trace-printk)

;; Control flow helpers
(def helper-tail-call dsl/helper-tail-call)
(def helper-loop dsl/helper-loop)

;; Cgroup helpers
(def helper-get-current-cgroup-id dsl/helper-get-current-cgroup-id)
(def helper-get-current-ancestor-cgroup-id dsl/helper-get-current-ancestor-cgroup-id)

;; Synchronization helpers
(def helper-spin-lock dsl/helper-spin-lock)
(def helper-spin-unlock dsl/helper-spin-unlock)

;; Utility helpers
(def helper-snprintf dsl/helper-snprintf)
(def helper-strncmp dsl/helper-strncmp)

;; High-level helper patterns
(def with-map-lookup dsl/with-map-lookup)
(def safe-probe-read dsl/safe-probe-read)
(def get-process-info dsl/get-process-info)
(def time-delta dsl/time-delta)
(def filter-by-pid dsl/filter-by-pid)
(def filter-by-uid dsl/filter-by-uid)
(def sample-one-in-n dsl/sample-one-in-n)
(def trace-println dsl/trace-println)
(def ringbuf-output-event dsl/ringbuf-output-event)
(def with-spinlock dsl/with-spinlock)
(def bounded-loop dsl/bounded-loop)
(def stack-allocate dsl/stack-allocate)
(def extract-pid dsl/extract-pid)
(def extract-tgid dsl/extract-tgid)
(def extract-uid dsl/extract-uid)
(def extract-gid dsl/extract-gid)

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

(defmacro with-perf-consumer
  "Create and manage perf event consumer with automatic cleanup"
  [& args]
  `(perf/with-perf-consumer ~@args))

(defmacro with-lsm-program
  "Attach LSM program and ensure detachment after use"
  [& args]
  `(lsm/with-lsm-program ~@args))

(defmacro with-lsm-hook
  "Load and attach LSM hook, ensure cleanup"
  [& args]
  `(lsm/with-lsm-hook ~@args))

;; High-level declarative macros
(defmacro defprogram
  "Define a named BPF program with assembled bytecode and metadata.
   See clj-ebpf.macros/defprogram for full documentation."
  [name & opts]
  `(macros/defprogram ~name ~@opts))

(defmacro defmap-spec
  "Define a reusable BPF map specification.
   See clj-ebpf.macros/defmap-spec for full documentation."
  [name & opts]
  `(macros/defmap-spec ~name ~@opts))

(defmacro with-bpf-script
  "Execute body with BPF maps, programs, and attachments, ensuring cleanup.
   See clj-ebpf.macros/with-bpf-script for full documentation."
  [config & body]
  `(macros/with-bpf-script ~config ~@body))

;; Convenience functions for declarative macros
(def load-defprogram macros/load-defprogram)
(def create-defmap macros/create-defmap)

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
  "0.1.1")

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
