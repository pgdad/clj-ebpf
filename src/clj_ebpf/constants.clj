(ns clj-ebpf.constants
  "BPF constants and enumerations from linux/bpf.h")

;; BPF syscall number (x86_64)
(def ^:const BPF_SYSCALL_NR 321)

;; BPF commands
(def bpf-cmd
  {:map-create 0
   :map-lookup-elem 1
   :map-update-elem 2
   :map-delete-elem 3
   :map-get-next-key 4
   :prog-load 5
   :obj-pin 6
   :obj-get 7
   :prog-attach 8
   :prog-detach 9
   :prog-test-run 10
   :prog-get-next-id 11
   :map-get-next-id 12
   :prog-get-fd-by-id 13
   :map-get-fd-by-id 14
   :obj-get-info-by-fd 15
   :prog-query 16
   :raw-tracepoint-open 17
   :btf-load 18
   :btf-get-fd-by-id 19
   :task-fd-query 20
   :map-lookup-and-delete-elem 21
   :map-freeze 22
   :btf-get-next-id 23
   :map-lookup-batch 24
   :map-lookup-and-delete-batch 25
   :map-update-batch 26
   :map-delete-batch 27
   :link-create 28
   :link-update 29
   :link-get-fd-by-id 30
   :link-get-next-id 31
   :enable-stats 32
   :iter-create 33
   :link-detach 34
   :prog-bind-map 35})

(def cmd->int
  (into {} (map (fn [[k v]] [k v]) bpf-cmd)))

(def int->cmd
  (into {} (map (fn [[k v]] [v k]) bpf-cmd)))

;; BPF map types
(def map-type
  {:unspec 0
   :hash 1
   :array 2
   :prog-array 3
   :perf-event-array 4
   :percpu-hash 5
   :percpu-array 6
   :stack-trace 7
   :cgroup-array 8
   :lru-hash 9
   :lru-percpu-hash 10
   :lpm-trie 11
   :array-of-maps 12
   :hash-of-maps 13
   :devmap 14
   :sockmap 15
   :cpumap 16
   :xskmap 17
   :sockhash 18
   :cgroup-storage 19
   :reuseport-sockarray 20
   :percpu-cgroup-storage 21
   :queue 22
   :stack 23
   :sk-storage 24
   :devmap-hash 25
   :struct-ops 26
   :ringbuf 27
   :inode-storage 28
   :task-storage 29
   :bloom-filter 30})

(def map-type->int
  (into {} (map (fn [[k v]] [k v]) map-type)))

(def int->map-type
  (into {} (map (fn [[k v]] [v k]) map-type)))

;; BPF program types
(def prog-type
  {:unspec 0
   :socket-filter 1
   :kprobe 2
   :sched-cls 3
   :sched-act 4
   :tracepoint 5
   :xdp 6
   :perf-event 7
   :cgroup-skb 8
   :cgroup-sock 9
   :lwt-in 10
   :lwt-out 11
   :lwt-xmit 12
   :sock-ops 13
   :sk-skb 14
   :cgroup-device 15
   :sk-msg 16
   :raw-tracepoint 17
   :cgroup-sock-addr 18
   :lwt-seg6local 19
   :lirc-mode2 20
   :sk-reuseport 21
   :flow-dissector 22
   :cgroup-sysctl 23
   :raw-tracepoint-writable 24
   :cgroup-sockopt 25
   :tracing 26
   :struct-ops 27
   :ext 28
   :lsm 29
   :sk-lookup 30
   :syscall 31})

(def prog-type->int
  (into {} (map (fn [[k v]] [k v]) prog-type)))

(def int->prog-type
  (into {} (map (fn [[k v]] [v k]) prog-type)))

;; BPF attach types
(def attach-type
  {:cgroup-inet-ingress 0
   :cgroup-inet-egress 1
   :cgroup-inet-sock-create 2
   :cgroup-sock-ops 3
   :sk-skb-stream-parser 4
   :sk-skb-stream-verdict 5
   :cgroup-device 6
   :sk-msg-verdict 7
   :cgroup-inet4-bind 8
   :cgroup-inet6-bind 9
   :cgroup-inet4-connect 10
   :cgroup-inet6-connect 11
   :cgroup-inet4-post-bind 12
   :cgroup-inet6-post-bind 13
   :cgroup-udp4-sendmsg 14
   :cgroup-udp6-sendmsg 15
   :lirc-mode2 16
   :flow-dissector 17
   :cgroup-sysctl 18
   :cgroup-udp4-recvmsg 19
   :cgroup-udp6-recvmsg 20
   :cgroup-getsockopt 21
   :cgroup-setsockopt 22
   :trace-raw-tp 23
   :trace-fentry 24
   :trace-fexit 25
   :modify-return 26
   :lsm-mac 27
   :trace-iter 28
   :cgroup-inet4-getpeername 29
   :cgroup-inet6-getpeername 30
   :cgroup-inet4-getsockname 31
   :cgroup-inet6-getsockname 32
   :xdp-devmap 33
   :cgroup-inet-sock-release 34
   :xdp-cpumap 35
   :sk-lookup 36
   :xdp 37
   :sk-skb-verdict 38
   :sk-reuseport-select 39
   :sk-reuseport-select-or-migrate 40
   :perf-event 41})

(def attach-type->int
  (into {} (map (fn [[k v]] [k v]) attach-type)))

(def int->attach-type
  (into {} (map (fn [[k v]] [v k]) attach-type)))

;; Map flags
(def map-flags
  {:no-prealloc 0x01
   :no-common-lru 0x02
   :numa-node 0x04
   :rdonly 0x08
   :wronly 0x10
   :stack-build-id 0x20
   :zero-seed 0x40
   :rdonly-prog 0x80
   :wronly-prog 0x100
   :clone 0x200
   :mmapable 0x400
   :preserve-elems 0x800
   :inner-map 0x1000})

;; Map update flags
(def map-update-flags
  {:any 0
   :noexist 1  ; create new element or fail
   :exist 2    ; update existing element or fail
   :lock 4})   ; spin_lock-ed map_lookup/map_update

;; Program load flags
(def prog-load-flags
  {:strict-alignment 0x01
   :any-alignment 0x02
   :test-state-freq 0x08
   :sleepable 0x10
   :test-run-on-netns 0x20})

;; BPF object pinning
(def pin-type
  {:none 0
   :obj-ns 1})

;; Helper function IDs (subset for MVP)
(def helper-func
  {:unspec 0
   :map-lookup-elem 1
   :map-update-elem 2
   :map-delete-elem 3
   :probe-read 4
   :ktime-get-ns 5
   :trace-printk 6
   :get-prandom-u32 7
   :get-smp-processor-id 8
   :skb-store-bytes 9
   :l3-csum-replace 10
   :l4-csum-replace 11
   :tail-call 12
   :clone-redirect 13
   :get-current-pid-tgid 14
   :get-current-uid-gid 15
   :get-current-comm 16
   :get-cgroup-classid 17
   :skb-vlan-push 18
   :skb-vlan-pop 19
   :skb-get-tunnel-key 20
   :skb-set-tunnel-key 21
   :perf-event-read 22
   :redirect 23
   :get-route-realm 24
   :perf-event-output 25
   :skb-load-bytes 26
   :get-stackid 27
   :csum-diff 28
   :skb-get-tunnel-opt 29
   :skb-set-tunnel-opt 30
   :ringbuf-output 130
   :ringbuf-reserve 131
   :ringbuf-submit 132
   :ringbuf-discard 133
   :ringbuf-query 134})

;; Perf event types
(def perf-type
  {:hardware 0
   :software 1
   :tracepoint 2
   :hw-cache 3
   :raw 4
   :breakpoint 5})

;; Perf event config for software events
(def perf-sw-config
  {:cpu-clock 0
   :task-clock 1
   :page-faults 2
   :context-switches 3
   :cpu-migrations 4
   :page-faults-min 5
   :page-faults-maj 6
   :alignment-faults 7
   :emulation-faults 8
   :dummy 9
   :bpf-output 10})

;; Perf event sample format
(def perf-sample-type
  {:ip 0x01
   :tid 0x02
   :time 0x04
   :addr 0x08
   :read 0x10
   :callchain 0x20
   :id 0x40
   :cpu 0x80
   :period 0x100
   :stream-id 0x200
   :raw 0x400
   :branch-stack 0x800
   :regs-user 0x1000
   :stack-user 0x2000
   :weight 0x4000
   :data-src 0x8000
   :identifier 0x10000
   :transaction 0x20000
   :regs-intr 0x40000})

;; IOCTL commands
(def perf-event-ioc
  {:enable 0x2400
   :disable 0x2401
   :refresh 0x2402
   :reset 0x2403
   :period 0x2404
   :set-output 0x2405
   :set-filter 0x2406
   :id 0x2407
   :set-bpf 0x2408
   :pause-output 0x2409
   :query-bpf 0x240a
   :modify-attributes 0x240b})

;; Error codes
(def errno
  {:perm 1          ; Operation not permitted
   :noent 2         ; No such file or directory
   :intr 4          ; Interrupted system call
   :io 5            ; I/O error
   :badf 9          ; Bad file descriptor
   :nomem 12        ; Out of memory
   :acces 13        ; Permission denied
   :fault 14        ; Bad address
   :exist 17        ; File exists
   :nodev 19        ; No such device
   :inval 22        ; Invalid argument
   :nospc 28        ; No space left on device
   :range 34        ; Math result not representable
   :nosys 38        ; Function not implemented
   :busy 16         ; Device or resource busy
   :notsup 95})     ; Operation not supported

;; Maximum sizes
(def ^:const BPF_OBJ_NAME_LEN 16)
(def ^:const BPF_TAG_SIZE 8)
(def ^:const BPF_LOG_BUF_SIZE (* 256 1024)) ; 256KB verifier log buffer

;; Utility functions
(defn cmd->num
  "Convert command keyword to integer"
  [cmd]
  (get cmd->int cmd))

(defn map-type->num
  "Convert map type keyword to integer"
  [type]
  (get map-type->int type))

(defn prog-type->num
  "Convert program type keyword to integer"
  [type]
  (get prog-type->int type))

(defn attach-type->num
  "Convert attach type keyword to integer"
  [type]
  (get attach-type->int type))

(defn flags->bits
  "Convert flag keywords to bitwise OR of values"
  [flag-map flags]
  (reduce (fn [acc flag]
            (bit-or acc (get flag-map flag 0)))
          0
          flags))
