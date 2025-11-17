(ns clj-ebpf.cgroup
  "Cgroup v2 BPF program attachment for container and process control"
  (:require [clj-ebpf.constants :as const]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.programs :as programs])
  (:import [java.lang.foreign Arena MemorySegment ValueLayout]
           [java.nio.file Files Paths LinkOption]
           [java.nio.file.attribute FileAttribute]))

;; ============================================================================
;; Cgroup Constants
;; ============================================================================

;; Cgroup v2 default mount point
(def ^:const DEFAULT_CGROUP_PATH "/sys/fs/cgroup")

;; Cgroup BPF attach flags
(def cgroup-attach-flags
  {:none 0
   :override 1          ; Replace existing program
   :multi 2             ; Allow multiple programs (if supported)
   :replace 4})         ; Replace specific program by ID

;; Cgroup program return values
(def cgroup-return-code
  {:ok 1               ; Allow operation
   :reject 0})         ; Deny operation

;; Program type to attach type mappings (most common)
(def prog-type->attach-type
  {:cgroup-skb {:ingress :cgroup-inet-ingress
                :egress :cgroup-inet-egress}
   :cgroup-sock :cgroup-inet-sock-create
   :cgroup-device :cgroup-device
   :cgroup-sysctl :cgroup-sysctl
   :cgroup-sockopt {:getsockopt :cgroup-getsockopt
                    :setsockopt :cgroup-setsockopt}})

;; ============================================================================
;; Cgroup File Descriptor Management
;; ============================================================================

(defn- open-cgroup
  "Open a cgroup directory and return file descriptor.

  Uses open syscall (syscall 2) with O_RDONLY | O_DIRECTORY flags."
  [cgroup-path]
  (let [path-seg (utils/string->segment cgroup-path)
        O_RDONLY 0
        O_DIRECTORY 0x10000
        flags (bit-or O_RDONLY O_DIRECTORY)
        result (syscall/raw-syscall 2 path-seg flags 0)] ; open syscall
    (when (neg? result)
      (throw (ex-info "Failed to open cgroup directory"
                     {:path cgroup-path :errno (- result)})))
    result))

(defn get-cgroup-fd
  "Get file descriptor for a cgroup path.

  Parameters:
  - cgroup-path: Absolute path to cgroup directory (e.g., \"/sys/fs/cgroup/my-container\")
                 or relative path from default cgroup root

  Returns the cgroup file descriptor.

  Example:
    (get-cgroup-fd \"/sys/fs/cgroup\")
    (get-cgroup-fd \"my-container\") ; relative to /sys/fs/cgroup"
  [cgroup-path]
  (let [full-path (if (.startsWith cgroup-path "/")
                    cgroup-path
                    (str DEFAULT_CGROUP_PATH "/" cgroup-path))]
    (open-cgroup full-path)))

(defn close-cgroup
  "Close a cgroup file descriptor.

  Parameters:
  - cgroup-fd: Cgroup file descriptor

  Example:
    (close-cgroup fd)"
  [cgroup-fd]
  (syscall/close-fd cgroup-fd))

(defn cgroup-exists?
  "Check if a cgroup path exists.

  Parameters:
  - cgroup-path: Path to cgroup directory

  Returns true if the cgroup exists, false otherwise."
  [cgroup-path]
  (let [full-path (if (.startsWith cgroup-path "/")
                    cgroup-path
                    (str DEFAULT_CGROUP_PATH "/" cgroup-path))
        path (Paths/get full-path (into-array String []))]
    (Files/exists path (into-array LinkOption []))))

;; ============================================================================
;; BPF Program Attach/Detach Syscalls
;; ============================================================================

(defn- prog-attach-attr->segment
  "Create memory segment for bpf_attr union for BPF_PROG_ATTACH.

  Structure (from linux/bpf.h):
  struct {
    __u32 target_fd;      // cgroup fd
    __u32 attach_bpf_fd;  // program fd
    __u32 attach_type;
    __u32 attach_flags;
    __u32 replace_bpf_fd; // for BPF_F_REPLACE
  }"
  [target-fd prog-fd attach-type-int attach-flags replace-fd]
  (let [attr (utils/pack-struct [[:u32 target-fd]
                                  [:u32 prog-fd]
                                  [:u32 attach-type-int]
                                  [:u32 attach-flags]
                                  [:u32 (or replace-fd 0)]])]
    (utils/bytes->segment attr)))

(defn- prog-detach-attr->segment
  "Create memory segment for bpf_attr union for BPF_PROG_DETACH.

  Structure:
  struct {
    __u32 target_fd;      // cgroup fd
    __u32 attach_bpf_fd;  // program fd (0 to detach all)
    __u32 attach_type;
  }"
  [target-fd prog-fd attach-type-int]
  (let [attr (utils/pack-struct [[:u32 target-fd]
                                  [:u32 (or prog-fd 0)]
                                  [:u32 attach-type-int]])]
    (utils/bytes->segment attr)))

(defn prog-attach-cgroup
  "Attach BPF program to a cgroup (low-level syscall wrapper).

  Parameters:
  - cgroup-fd: Cgroup file descriptor
  - prog-fd: BPF program file descriptor
  - attach-type: Attach type keyword (e.g., :cgroup-inet-ingress)
  - flags: Attach flags (default :none)
  - replace-fd: Program FD to replace (for :replace flag)

  Returns 0 on success, throws on error.

  Example:
    (prog-attach-cgroup cgroup-fd prog-fd :cgroup-inet-ingress :override)"
  [cgroup-fd prog-fd attach-type & {:keys [flags replace-fd]
                                    :or {flags :none replace-fd nil}}]
  (let [attach-type-int (const/attach-type->num attach-type)
        flags-int (get cgroup-attach-flags flags 0)
        attr-seg (prog-attach-attr->segment cgroup-fd prog-fd attach-type-int
                                           flags-int replace-fd)
        result (syscall/bpf-syscall :prog-attach attr-seg)]
    (when (neg? result)
      (throw (ex-info "Failed to attach program to cgroup"
                     {:cgroup-fd cgroup-fd
                      :prog-fd prog-fd
                      :attach-type attach-type
                      :errno (- result)})))
    result))

(defn prog-detach-cgroup
  "Detach BPF program from a cgroup (low-level syscall wrapper).

  Parameters:
  - cgroup-fd: Cgroup file descriptor
  - attach-type: Attach type keyword
  - prog-fd: Program FD to detach (nil to detach all)

  Returns 0 on success, throws on error.

  Example:
    (prog-detach-cgroup cgroup-fd :cgroup-inet-ingress prog-fd)"
  [cgroup-fd attach-type & {:keys [prog-fd]
                            :or {prog-fd nil}}]
  (let [attach-type-int (const/attach-type->num attach-type)
        attr-seg (prog-detach-attr->segment cgroup-fd prog-fd attach-type-int)
        result (syscall/bpf-syscall :prog-detach attr-seg)]
    (when (neg? result)
      (throw (ex-info "Failed to detach program from cgroup"
                     {:cgroup-fd cgroup-fd
                      :attach-type attach-type
                      :errno (- result)})))
    result))

;; ============================================================================
;; High-Level Cgroup Attachment API
;; ============================================================================

(defn attach-cgroup-program
  "Attach BPF program to a cgroup (high-level API).

  Parameters:
  - cgroup-path: Path to cgroup (absolute or relative to /sys/fs/cgroup)
  - prog-fd: BPF program file descriptor
  - attach-type: Attach type keyword (e.g., :cgroup-inet-ingress, :cgroup-device)
  - options: Map of options:
    - :flags - Attach flags (:none, :override, :multi, :replace)
    - :replace-fd - Program FD to replace (with :replace flag)
    - :auto-close-cgroup - Close cgroup FD after attach (default true)

  Returns a map with :cgroup-fd and :attach-type for use with detach.

  Example:
    (attach-cgroup-program \"my-container\" prog-fd :cgroup-inet-ingress
                          :flags :override)"
  [cgroup-path prog-fd attach-type & {:keys [flags replace-fd auto-close-cgroup]
                                      :or {flags :none auto-close-cgroup true}}]
  (let [cgroup-fd (get-cgroup-fd cgroup-path)]
    (try
      (prog-attach-cgroup cgroup-fd prog-fd attach-type
                         :flags flags
                         :replace-fd replace-fd)
      {:cgroup-fd (if auto-close-cgroup nil cgroup-fd)
       :cgroup-path cgroup-path
       :attach-type attach-type
       :prog-fd prog-fd}
      (finally
        (when auto-close-cgroup
          (close-cgroup cgroup-fd))))))

(defn detach-cgroup-program
  "Detach BPF program from a cgroup (high-level API).

  Parameters:
  - cgroup-path: Path to cgroup
  - attach-type: Attach type keyword
  - prog-fd: Program FD to detach (nil to detach all)

  Example:
    (detach-cgroup-program \"my-container\" :cgroup-inet-ingress prog-fd)

  Or using attachment info:
    (let [info (attach-cgroup-program \"my-container\" prog-fd :cgroup-inet-ingress)]
      (detach-cgroup-program (:cgroup-path info) (:attach-type info) (:prog-fd info)))"
  [cgroup-path attach-type & {:keys [prog-fd]
                              :or {prog-fd nil}}]
  (let [cgroup-fd (get-cgroup-fd cgroup-path)]
    (try
      (prog-detach-cgroup cgroup-fd attach-type :prog-fd prog-fd)
      (finally
        (close-cgroup cgroup-fd)))))

;; ============================================================================
;; Cgroup-Specific Program Loaders
;; ============================================================================

(defn load-cgroup-skb-program
  "Load a cgroup SKB program for network filtering.

  Parameters:
  - bytecode: BPF bytecode
  - direction: :ingress or :egress
  - options: Program load options (see programs/load-program)

  Returns program file descriptor.

  Example:
    (load-cgroup-skb-program bytecode :ingress :prog-name \"skb_filter\" :license \"GPL\")"
  [bytecode direction & {:keys [prog-name license log-level log-size]
                         :or {license "GPL" log-level 0 log-size 0}}]
  (when-not (#{:ingress :egress} direction)
    (throw (ex-info "Invalid direction, must be :ingress or :egress"
                   {:direction direction})))
  (programs/load-program bytecode
                        :prog-type :cgroup-skb
                        :prog-name (or prog-name (str "cgroup_skb_" (name direction)))
                        :license license
                        :log-level log-level
                        :log-size log-size))

(defn load-cgroup-sock-program
  "Load a cgroup socket program for socket operations control.

  Use for controlling socket creation, bind, connect operations.

  Example:
    (load-cgroup-sock-program bytecode :prog-name \"sock_filter\" :license \"GPL\")"
  [bytecode & {:keys [prog-name license log-level log-size]
               :or {license "GPL" log-level 0 log-size 0}}]
  (programs/load-program bytecode
                        :prog-type :cgroup-sock
                        :prog-name (or prog-name "cgroup_sock")
                        :license license
                        :log-level log-level
                        :log-size log-size))

(defn load-cgroup-device-program
  "Load a cgroup device program for device access control.

  Controls access to devices (character and block devices).

  Example:
    (load-cgroup-device-program bytecode :prog-name \"device_filter\" :license \"GPL\")"
  [bytecode & {:keys [prog-name license log-level log-size]
               :or {license "GPL" log-level 0 log-size 0}}]
  (programs/load-program bytecode
                        :prog-type :cgroup-device
                        :prog-name (or prog-name "cgroup_device")
                        :license license
                        :log-level log-level
                        :log-size log-size))

(defn load-cgroup-sysctl-program
  "Load a cgroup sysctl program for sysctl access control.

  Controls access to sysctl parameters.

  Example:
    (load-cgroup-sysctl-program bytecode :prog-name \"sysctl_filter\" :license \"GPL\")"
  [bytecode & {:keys [prog-name license log-level log-size]
               :or {license "GPL" log-level 0 log-size 0}}]
  (programs/load-program bytecode
                        :prog-type :cgroup-sysctl
                        :prog-name (or prog-name "cgroup_sysctl")
                        :license license
                        :log-level log-level
                        :log-size log-size))

;; ============================================================================
;; Convenience Functions
;; ============================================================================

(defn setup-cgroup-skb
  "Setup cgroup SKB filter (load program and attach).

  Convenience function that:
  1. Loads the BPF program
  2. Attaches it to the cgroup

  Parameters:
  - cgroup-path: Path to cgroup
  - bytecode: BPF bytecode
  - direction: :ingress or :egress
  - options: Combined program load and attach options

  Returns a map with :prog-fd and :attach-info for cleanup.

  Example:
    (def setup (setup-cgroup-skb \"my-container\" bytecode :ingress
                                :prog-name \"filter\" :flags :override))
    ;; ... later ...
    (teardown-cgroup-program setup)"
  [cgroup-path bytecode direction & {:keys [prog-name flags]
                                     :or {flags :override}
                                     :as options}]
  (let [prog-fd (load-cgroup-skb-program bytecode direction options)
        attach-type (get-in prog-type->attach-type [:cgroup-skb direction])
        attach-info (attach-cgroup-program cgroup-path prog-fd attach-type
                                          :flags flags)]
    {:prog-fd prog-fd
     :attach-info attach-info}))

(defn setup-cgroup-sock
  "Setup cgroup socket filter (load program and attach).

  Example:
    (def setup (setup-cgroup-sock \"my-container\" bytecode
                                 :prog-name \"sock_filter\"))"
  [cgroup-path bytecode & {:keys [prog-name flags]
                           :or {flags :override}
                           :as options}]
  (let [prog-fd (load-cgroup-sock-program bytecode options)
        attach-info (attach-cgroup-program cgroup-path prog-fd
                                          :cgroup-inet-sock-create
                                          :flags flags)]
    {:prog-fd prog-fd
     :attach-info attach-info}))

(defn setup-cgroup-device
  "Setup cgroup device filter (load program and attach).

  Example:
    (def setup (setup-cgroup-device \"my-container\" bytecode
                                   :prog-name \"device_filter\"))"
  [cgroup-path bytecode & {:keys [prog-name flags]
                           :or {flags :override}
                           :as options}]
  (let [prog-fd (load-cgroup-device-program bytecode options)
        attach-info (attach-cgroup-program cgroup-path prog-fd
                                          :cgroup-device
                                          :flags flags)]
    {:prog-fd prog-fd
     :attach-info attach-info}))

(defn teardown-cgroup-program
  "Teardown cgroup program setup created by setup-* functions.

  Parameters:
  - setup: Map returned by setup-cgroup-* functions with :prog-fd and :attach-info

  Example:
    (teardown-cgroup-program setup)"
  [{:keys [prog-fd attach-info]}]
  (try
    (detach-cgroup-program (:cgroup-path attach-info)
                          (:attach-type attach-info)
                          :prog-fd prog-fd)
    (finally
      (syscall/close-fd prog-fd))))

;; ============================================================================
;; Resource Management Macros
;; ============================================================================

(defmacro with-cgroup-program
  "Attach cgroup program and ensure detachment after use.

  Example:
    (with-cgroup-program [info (attach-cgroup-program \"my-container\"
                                                      prog-fd
                                                      :cgroup-inet-ingress)]
      ;; Program is attached
      (do-work))"
  [[binding attach-expr] & body]
  `(let [~binding ~attach-expr
         info# ~binding]
     (try
       ~@body
       (finally
         (detach-cgroup-program (:cgroup-path info#)
                               (:attach-type info#)
                               :prog-fd (:prog-fd info#))))))

(defmacro with-cgroup-skb
  "Load and attach cgroup SKB program, ensure cleanup.

  Example:
    (with-cgroup-skb [setup (setup-cgroup-skb \"my-container\"
                                             bytecode
                                             :ingress)]
      ;; Program is loaded and attached
      (process-packets))"
  [[binding setup-expr] & body]
  `(let [~binding ~setup-expr
         setup# ~binding]
     (try
       ~@body
       (finally
         (teardown-cgroup-program setup#)))))

;; ============================================================================
;; Cgroup Utilities
;; ============================================================================

(defn get-current-cgroup
  "Get the cgroup path of the current process.

  Reads /proc/self/cgroup and returns the cgroup v2 path.

  Returns the cgroup path relative to /sys/fs/cgroup."
  []
  (try
    (let [cgroup-content (slurp "/proc/self/cgroup")
          ;; cgroup v2 format: 0::/path
          lines (clojure.string/split-lines cgroup-content)
          cgroup-v2-line (first (filter #(.startsWith % "0::") lines))]
      (if cgroup-v2-line
        (subs cgroup-v2-line 3) ; Remove "0::" prefix
        "/"))
    (catch Exception e
      (throw (ex-info "Failed to read current cgroup" {:error (.getMessage e)})))))

(defn list-cgroup-children
  "List child cgroups of a given cgroup path.

  Parameters:
  - cgroup-path: Path to cgroup directory

  Returns a vector of child cgroup names."
  [cgroup-path]
  (let [full-path (if (.startsWith cgroup-path "/")
                    cgroup-path
                    (str DEFAULT_CGROUP_PATH "/" cgroup-path))
        dir (clojure.java.io/file full-path)]
    (if (.exists dir)
      (->> (.listFiles dir)
           (filter #(.isDirectory %))
           (map #(.getName %))
           (into []))
      [])))
