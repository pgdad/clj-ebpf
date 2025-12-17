(ns clj-ebpf.arch
  "Architecture detection and platform-specific constants.

   Provides runtime detection of CPU architecture and appropriate
   syscall numbers, libc paths, and other platform-specific values.")

;; ============================================================================
;; Architecture Detection
;; ============================================================================

(def ^:private arch-mapping
  "Map JVM os.arch values to our canonical architecture keywords"
  {"amd64"   :x86_64
   "x86_64"  :x86_64
   "aarch64" :arm64
   "arm64"   :arm64
   "s390x"   :s390x
   "s390"    :s390x
   "ppc64le" :ppc64le
   "ppc64"   :ppc64le
   "riscv64" :riscv64})

(def current-arch
  "The detected CPU architecture as a keyword.
   One of: :x86_64, :arm64, :s390x, :ppc64le, :riscv64, or :unknown"
  (let [arch-str (System/getProperty "os.arch")]
    (get arch-mapping arch-str :unknown)))

(def arch-name
  "Human-readable architecture name"
  (case current-arch
    :x86_64  "x86-64 (AMD64)"
    :arm64   "ARM64 (AArch64)"
    :s390x   "IBM s390x"
    :ppc64le "PowerPC 64-bit LE"
    :riscv64 "RISC-V 64-bit"
    (str "Unknown (" (System/getProperty "os.arch") ")")))

;; ============================================================================
;; Syscall Numbers by Architecture
;; ============================================================================

(def ^:private syscall-numbers
  "Linux syscall numbers by architecture.

   Sources:
   - x86_64:  arch/x86/entry/syscalls/syscall_64.tbl
   - arm64:   include/uapi/asm-generic/unistd.h (uses generic numbers)
   - s390x:   arch/s390/kernel/syscalls/syscall.tbl
   - ppc64le: arch/powerpc/kernel/syscalls/syscall.tbl
   - riscv64: include/uapi/asm-generic/unistd.h (uses generic numbers)"
  {:x86_64
   {:bpf             321
    :perf-event-open 298
    :mmap            9
    :munmap          11
    :socket          41
    :bind            49
    :sendto          44
    :recvfrom        45
    :close           3
    :read            0
    :write           1
    :ioctl           16
    :epoll-create1   291
    :epoll-ctl       233
    :epoll-wait      232
    :epoll-pwait     281}

   :arm64
   {:bpf             280
    :perf-event-open 241
    :mmap            222
    :munmap          215
    :socket          198
    :bind            200
    :sendto          206
    :recvfrom        207
    :close           57
    :read            63
    :write           64
    :ioctl           29
    :epoll-create1   20
    :epoll-ctl       21
    :epoll-wait      -1   ; Not available on arm64, use epoll_pwait
    :epoll-pwait     22}

   :s390x
   {:bpf             351
    :perf-event-open 331
    :mmap            90
    :munmap          91
    :socket          359
    :bind            361
    :sendto          369
    :recvfrom        371
    :close           6
    :read            3
    :write           4
    :ioctl           54
    :epoll-create1   327
    :epoll-ctl       250
    :epoll-wait      251
    :epoll-pwait     312}

   :ppc64le
   {:bpf             361
    :perf-event-open 319
    :mmap            90
    :munmap          91
    :socket          326
    :bind            327
    :sendto          335
    :recvfrom        337
    :close           6
    :read            3
    :write           4
    :ioctl           54
    :epoll-create1   315
    :epoll-ctl       237
    :epoll-wait      238
    :epoll-pwait     303}

   :riscv64
   {:bpf             280
    :perf-event-open 241
    :mmap            222
    :munmap          215
    :socket          198
    :bind            200
    :sendto          206
    :recvfrom        207
    :close           57
    :read            63
    :write           64
    :ioctl           29
    :epoll-create1   20
    :epoll-ctl       21
    :epoll-wait      -1   ; Not available on riscv64, use epoll_pwait
    :epoll-pwait     22}})

(defn get-syscall-nr
  "Get the syscall number for the given syscall on the current architecture.

   Arguments:
   - syscall-name: Keyword like :bpf, :perf-event-open, :mmap, etc.

   Returns the syscall number, or throws if architecture is unsupported."
  [syscall-name]
  (if-let [arch-syscalls (get syscall-numbers current-arch)]
    (if-let [nr (get arch-syscalls syscall-name)]
      (if (neg? nr)
        (throw (ex-info (str "Syscall " syscall-name " not available on " arch-name)
                        {:syscall syscall-name :arch current-arch}))
        nr)
      (throw (ex-info (str "Unknown syscall: " syscall-name)
                      {:syscall syscall-name :arch current-arch})))
    (throw (ex-info (str "Unsupported architecture: " arch-name)
                    {:arch current-arch
                     :os-arch (System/getProperty "os.arch")}))))

;; Commonly used syscall numbers as vars for performance
(def ^:const BPF_SYSCALL_NR (delay (get-syscall-nr :bpf)))
(def ^:const PERF_EVENT_OPEN_SYSCALL_NR (delay (get-syscall-nr :perf-event-open)))
(def ^:const MMAP_SYSCALL_NR (delay (get-syscall-nr :mmap)))
(def ^:const MUNMAP_SYSCALL_NR (delay (get-syscall-nr :munmap)))
(def ^:const SOCKET_SYSCALL_NR (delay (get-syscall-nr :socket)))
(def ^:const CLOSE_SYSCALL_NR (delay (get-syscall-nr :close)))
(def ^:const IOCTL_SYSCALL_NR (delay (get-syscall-nr :ioctl)))
(def ^:const EPOLL_CREATE1_SYSCALL_NR (delay (get-syscall-nr :epoll-create1)))
(def ^:const EPOLL_CTL_SYSCALL_NR (delay (get-syscall-nr :epoll-ctl)))
(def ^:const EPOLL_PWAIT_SYSCALL_NR (delay (get-syscall-nr :epoll-pwait)))

;; ============================================================================
;; Library Paths by Architecture
;; ============================================================================

(def ^:private libc-paths
  "Potential libc.so paths by architecture, in order of preference"
  {:x86_64
   ["/lib/x86_64-linux-gnu/libc.so.6"      ; Debian/Ubuntu
    "/lib64/libc.so.6"                      ; RHEL/CentOS/Fedora
    "/usr/lib64/libc.so.6"                  ; Some distros
    "/lib/libc.so.6"]                       ; Fallback

   :arm64
   ["/lib/aarch64-linux-gnu/libc.so.6"     ; Debian/Ubuntu
    "/lib64/libc.so.6"                      ; RHEL/CentOS
    "/usr/lib64/libc.so.6"
    "/lib/libc.so.6"]

   :s390x
   ["/lib/s390x-linux-gnu/libc.so.6"       ; Debian/Ubuntu
    "/lib64/libc.so.6"                      ; RHEL
    "/usr/lib64/libc.so.6"
    "/lib/libc.so.6"]

   :ppc64le
   ["/lib/powerpc64le-linux-gnu/libc.so.6" ; Debian/Ubuntu
    "/lib64/libc.so.6"                      ; RHEL
    "/usr/lib64/libc.so.6"
    "/lib/libc.so.6"]

   :riscv64
   ["/lib/riscv64-linux-gnu/libc.so.6"     ; Debian/Ubuntu
    "/lib64/libc.so.6"
    "/usr/lib64/libc.so.6"
    "/lib/libc.so.6"]})

(defn find-libc-path
  "Find the path to libc.so on the current system.

   Returns the first existing libc path for the current architecture,
   or nil if no libc could be found."
  []
  (let [paths (get libc-paths current-arch
                   ;; Fallback paths for unknown architectures
                   ["/lib64/libc.so.6" "/lib/libc.so.6"])]
    (first (filter #(.exists (java.io.File. ^String %)) paths))))

(def libc-path
  "The detected libc.so path for the current system.
   Memoized for performance."
  (delay
    (or (find-libc-path)
        (throw (ex-info "Could not find libc.so"
                        {:arch current-arch
                         :tried (get libc-paths current-arch)})))))

;; ============================================================================
;; Architecture-Specific Configuration
;; ============================================================================

(def ^:private arch-config
  "Architecture-specific configuration values"
  {:x86_64
   {:page-size 4096
    :pointer-size 8
    :endianness :little
    :has-bpf-trampoline true
    :has-kprobe-multi true}

   :arm64
   {:page-size 4096  ; Can be 16K or 64K on some configs
    :pointer-size 8
    :endianness :little
    :has-bpf-trampoline true
    :has-kprobe-multi true}

   :s390x
   {:page-size 4096
    :pointer-size 8
    :endianness :big
    :has-bpf-trampoline false
    :has-kprobe-multi false}

   :ppc64le
   {:page-size 65536  ; PowerPC typically uses 64K pages
    :pointer-size 8
    :endianness :little
    :has-bpf-trampoline false
    :has-kprobe-multi false}

   :riscv64
   {:page-size 4096
    :pointer-size 8
    :endianness :little
    :has-bpf-trampoline true
    :has-kprobe-multi true}})

(defn get-arch-config
  "Get architecture-specific configuration value.

   Arguments:
   - key: One of :page-size, :pointer-size, :endianness,
          :has-bpf-trampoline, :has-kprobe-multi

   Returns the value for the current architecture."
  [key]
  (get-in arch-config [current-arch key]
          ;; Sensible defaults for unknown architectures
          (case key
            :page-size 4096
            :pointer-size 8
            :endianness :little
            :has-bpf-trampoline false
            :has-kprobe-multi false
            nil)))

(def page-size
  "Page size for the current architecture"
  (get-arch-config :page-size))

(def pointer-size
  "Pointer size (in bytes) for the current architecture"
  (get-arch-config :pointer-size))

(def big-endian?
  "True if the current architecture is big-endian"
  (= :big (get-arch-config :endianness)))

;; ============================================================================
;; pt_regs Offsets for Kprobe Argument Access
;; ============================================================================

(def ^:private pt-regs-offsets
  "Offsets into the pt_regs structure for each architecture.

   These are used to read function arguments in kprobe handlers.
   The pt_regs structure layout varies by architecture.

   Sources:
   - x86_64:  arch/x86/include/asm/ptrace.h
   - arm64:   arch/arm64/include/uapi/asm/ptrace.h
   - s390x:   arch/s390/include/uapi/asm/ptrace.h
   - ppc64le: arch/powerpc/include/uapi/asm/ptrace.h
   - riscv64: arch/riscv/include/uapi/asm/ptrace.h"
  {:x86_64
   ;; struct pt_regs layout for x86_64:
   ;; r15=0, r14=8, r13=16, r12=24, rbp=32, rbx=40, r11=48, r10=56
   ;; r9=64, r8=72, rax=80, rcx=88, rdx=96, rsi=104, rdi=112, orig_rax=120
   {:rdi 112 :rsi 104 :rdx 96 :rcx 88 :r8 72 :r9 64
    :rax 80 :rbx 40 :rbp 32 :r10 56 :r11 48 :r12 24 :r13 16 :r14 8 :r15 0
    :rip 128 :rsp 152}

   :arm64
   ;; struct user_pt_regs for arm64:
   ;; regs[0-30] at offset 0, each 8 bytes
   ;; sp at 248, pc at 256, pstate at 264
   {:x0 0 :x1 8 :x2 16 :x3 24 :x4 32 :x5 40 :x6 48 :x7 56
    :x8 64 :x9 72 :x10 80 :x11 88 :x12 96 :x13 104 :x14 112 :x15 120
    :x16 128 :x17 136 :x18 144 :x19 152 :x20 160 :x21 168 :x22 176 :x23 184
    :x24 192 :x25 200 :x26 208 :x27 216 :x28 224 :x29 232 :x30 240
    :sp 248 :pc 256}

   :s390x
   ;; struct pt_regs for s390x (simplified):
   ;; gprs[0-15] starting at offset 0, each 8 bytes
   {:r0 0 :r1 8 :r2 16 :r3 24 :r4 32 :r5 40 :r6 48 :r7 56
    :r8 64 :r9 72 :r10 80 :r11 88 :r12 96 :r13 104 :r14 112 :r15 120}

   :ppc64le
   ;; struct pt_regs for ppc64le (simplified):
   ;; gpr[0-31] at offset 0, each 8 bytes
   {:r0 0 :r1 8 :r2 16 :r3 24 :r4 32 :r5 40 :r6 48 :r7 56
    :r8 64 :r9 72 :r10 80 :r11 88 :r12 96 :r13 104 :r14 112 :r15 120
    :r16 128 :r17 136 :r18 144 :r19 152 :r20 160 :r21 168 :r22 176 :r23 184
    :r24 192 :r25 200 :r26 208 :r27 216 :r28 224 :r29 232 :r30 240 :r31 248}

   :riscv64
   ;; struct user_regs_struct for riscv64:
   ;; pc at 0, then general regs starting at 8
   {:pc 0 :ra 8 :sp 16 :gp 24 :tp 32 :t0 40 :t1 48 :t2 56
    :s0 64 :s1 72 :a0 80 :a1 88 :a2 96 :a3 104 :a4 112 :a5 120
    :a6 128 :a7 136 :s2 144 :s3 152 :s4 160 :s5 168 :s6 176 :s7 184
    :s8 192 :s9 200 :s10 208 :s11 216 :t3 224 :t4 232 :t5 240 :t6 248}})

(def ^:private kprobe-arg-regs
  "Registers used for function arguments in kprobes, in order (arg0, arg1, ...).

   These follow the platform ABI for function calling conventions."
  {:x86_64  [:rdi :rsi :rdx :rcx :r8 :r9]  ; System V AMD64 ABI
   :arm64   [:x0 :x1 :x2 :x3 :x4 :x5 :x6 :x7]  ; AAPCS64
   :s390x   [:r2 :r3 :r4 :r5 :r6]  ; s390x ABI (r2-r6 for args)
   :ppc64le [:r3 :r4 :r5 :r6 :r7 :r8 :r9 :r10]  ; PowerPC ELFv2 ABI
   :riscv64 [:a0 :a1 :a2 :a3 :a4 :a5 :a6 :a7]})  ; RISC-V calling convention

(defn get-pt-regs-offset
  "Get the offset of a register in the pt_regs structure.

   Arguments:
   - reg: Register keyword (e.g., :rdi for x86_64, :x0 for arm64)

   Returns the byte offset into pt_regs, or throws if not found."
  [reg]
  (if-let [arch-regs (get pt-regs-offsets current-arch)]
    (if-let [offset (get arch-regs reg)]
      offset
      (throw (ex-info (str "Unknown register: " reg " for " arch-name)
                      {:reg reg :arch current-arch
                       :available (keys arch-regs)})))
    (throw (ex-info (str "pt_regs offsets not available for " arch-name)
                    {:arch current-arch}))))

(defn get-kprobe-arg-offset
  "Get the pt_regs offset for kprobe function argument N (0-indexed).

   This maps argument index -> register -> pt_regs offset.

   Arguments:
   - n: Argument index (0 = first argument, 1 = second, etc.)

   Returns the byte offset into pt_regs to read the argument value."
  [n]
  (if-let [arg-regs (get kprobe-arg-regs current-arch)]
    (if (< n (count arg-regs))
      (get-pt-regs-offset (nth arg-regs n))
      (throw (ex-info (str "Kprobe argument " n " exceeds max register args for " arch-name)
                      {:arg-index n :max-args (count arg-regs) :arch current-arch})))
    (throw (ex-info (str "Kprobe arg registers not defined for " arch-name)
                    {:arch current-arch}))))

(def kprobe-max-reg-args
  "Maximum number of function arguments passed in registers for kprobes"
  (count (get kprobe-arg-regs current-arch [])))

;; ============================================================================
;; Feature Detection
;; ============================================================================

(defn supported-arch?
  "Returns true if the current architecture is fully supported"
  []
  (contains? syscall-numbers current-arch))

(defn check-arch-support!
  "Throws an exception if the current architecture is not supported"
  []
  (when-not (supported-arch?)
    (throw (ex-info (str "Unsupported architecture: " arch-name
                         ". Supported: x86_64, arm64, s390x, ppc64le, riscv64")
                    {:arch current-arch
                     :os-arch (System/getProperty "os.arch")}))))

(defn arch-info
  "Returns a map of architecture information for diagnostics"
  []
  {:arch current-arch
   :arch-name arch-name
   :os-arch (System/getProperty "os.arch")
   :os-name (System/getProperty "os.name")
   :os-version (System/getProperty "os.version")
   :supported (supported-arch?)
   :libc-path (try @libc-path (catch Exception _ nil))
   :page-size page-size
   :pointer-size pointer-size
   :endianness (get-arch-config :endianness)
   :has-bpf-trampoline (get-arch-config :has-bpf-trampoline)
   :has-kprobe-multi (get-arch-config :has-kprobe-multi)})
