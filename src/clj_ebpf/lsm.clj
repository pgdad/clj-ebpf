(ns clj-ebpf.lsm
  "LSM (Linux Security Modules) BPF hook support for security policies"
  (:require [clj-ebpf.constants :as const]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.programs :as programs]))

;; ============================================================================
;; LSM Hook Points
;; ============================================================================

;; Common LSM hooks (subset - Linux has 200+ hooks)
(def lsm-hooks
  {:file-open "file_open"
   :file-permission "file_permission"
   :file-ioctl "file_ioctl"
   :file-lock "file_lock"
   :file-mprotect "file_mprotect"
   :bprm-check-security "bprm_check_security"
   :bprm-committed-creds "bprm_committed_creds"
   :task-kill "task_kill"
   :task-setpgid "task_setpgid"
   :task-getpgid "task_getpgid"
   :task-alloc "task_alloc"
   :task-free "task_free"
   :cred-prepare "cred_prepare"
   :socket-create "socket_create"
   :socket-bind "socket_bind"
   :socket-connect "socket_connect"
   :socket-listen "socket_listen"
   :socket-accept "socket_accept"
   :socket-sendmsg "socket_sendmsg"
   :socket-recvmsg "socket_recvmsg"
   :inode-create "inode_create"
   :inode-link "inode_link"
   :inode-unlink "inode_unlink"
   :inode-symlink "inode_symlink"
   :inode-mkdir "inode_mkdir"
   :inode-rmdir "inode_rmdir"
   :inode-rename "inode_rename"
   :inode-permission "inode_permission"
   :inode-setattr "inode_setattr"
   :inode-getattr "inode_getattr"
   :sb-mount "sb_mount"
   :sb-umount "sb_umount"
   :sb-pivotroot "sb_pivotroot"})

;; LSM return values
(def lsm-return-code
  {:allow 0        ; Allow the operation
   :deny -1})      ; Deny the operation (EPERM)

;; ============================================================================
;; BPF Link Creation for LSM
;; ============================================================================

(defn- link-create-attr->segment
  "Create memory segment for bpf_attr union for BPF_LINK_CREATE.

  Structure (from linux/bpf.h):
  struct {
    __u32 prog_fd;
    __u32 target_fd;      // 0 for LSM
    __u32 attach_type;    // BPF_LSM_MAC
    __u32 flags;
    union {
      __u32 target_btf_id; // BTF ID of LSM hook
      struct {
        __u64 iter_info;
        __u32 iter_info_len;
      };
    };
  };"
  [prog-fd attach-type target-btf-id]
  (let [attr (utils/pack-struct [[:u32 prog-fd]
                                  [:u32 0]              ; target_fd (0 for LSM)
                                  [:u32 attach-type]
                                  [:u32 0]              ; flags
                                  [:u32 target-btf-id]])] ; BTF ID
    (utils/bytes->segment attr)))

(defn create-lsm-link
  "Create a BPF link for LSM program attachment.

  Parameters:
  - prog-fd: LSM program file descriptor
  - target-btf-id: BTF ID of the LSM hook (0 for auto-detection)

  Returns the link file descriptor.

  Note: Requires kernel 5.7+ with LSM BPF enabled.

  Example:
    (create-lsm-link prog-fd 0)"
  [prog-fd target-btf-id]
  (let [attach-type-int (const/attach-type->num :lsm-mac)
        attr-seg (link-create-attr->segment prog-fd attach-type-int target-btf-id)
        result (syscall/bpf-syscall :link-create attr-seg)]
    (when (neg? result)
      (throw (ex-info "Failed to create LSM BPF link"
                     {:prog-fd prog-fd
                      :target-btf-id target-btf-id
                      :errno (- result)})))
    result))

(defn close-lsm-link
  "Close an LSM BPF link.

  Parameters:
  - link-fd: Link file descriptor

  Example:
    (close-lsm-link link-fd)"
  [link-fd]
  (syscall/close-fd link-fd))

;; ============================================================================
;; LSM Program Loading
;; ============================================================================

(defn load-lsm-program
  "Load an LSM BPF program.

  Parameters:
  - bytecode: BPF bytecode (byte array)
  - hook: LSM hook point keyword (e.g., :file-open, :bprm-check-security)
  - options: Map of options:
    - :prog-name - Program name (default: hook name)
    - :license - License string (default \"GPL\")
    - :log-level - Verifier log level (default 0)
    - :log-size - Log buffer size (default 0)
    - :expected-attach-type - Override attach type (default :lsm-mac)

  Returns program file descriptor.

  Example:
    (load-lsm-program bytecode :file-open
                      :prog-name \"file_open_filter\"
                      :license \"GPL\")"
  [bytecode hook & {:keys [prog-name license log-level log-size expected-attach-type]
                    :or {license "GPL" log-level 0 log-size 0
                         expected-attach-type :lsm-mac}}]
  (when-not (contains? lsm-hooks hook)
    (throw (ex-info "Invalid LSM hook" {:hook hook :available-hooks (keys lsm-hooks)})))

  (programs/load-program bytecode
                        :prog-type :lsm
                        :prog-name (or prog-name (get lsm-hooks hook))
                        :license license
                        :log-level log-level
                        :log-size log-size
                        :expected-attach-type expected-attach-type))

;; ============================================================================
;; High-Level LSM API
;; ============================================================================

(defn attach-lsm-program
  "Attach an LSM BPF program to a hook point.

  Parameters:
  - prog-fd: LSM program file descriptor
  - target-btf-id: BTF ID of the LSM hook (optional, default 0 for auto-detect)

  Returns a map with :prog-fd and :link-fd for cleanup.

  Example:
    (attach-lsm-program prog-fd 0)"
  [prog-fd & {:keys [target-btf-id]
              :or {target-btf-id 0}}]
  (let [link-fd (create-lsm-link prog-fd target-btf-id)]
    {:prog-fd prog-fd
     :link-fd link-fd}))

(defn detach-lsm-program
  "Detach an LSM BPF program.

  Parameters:
  - link-info: Map with :link-fd from attach-lsm-program

  Example:
    (detach-lsm-program link-info)"
  [{:keys [link-fd]}]
  (close-lsm-link link-fd))

;; ============================================================================
;; Convenience Functions
;; ============================================================================

(defn setup-lsm-hook
  "Setup LSM hook (load program and attach).

  Convenience function that:
  1. Loads the BPF program
  2. Attaches it to the LSM hook

  Parameters:
  - bytecode: BPF bytecode
  - hook: LSM hook point keyword
  - options: Program load and attach options

  Returns a map with :prog-fd and :link-fd for cleanup.

  Example:
    (def setup (setup-lsm-hook bytecode :file-open
                              :prog-name \"file_filter\"))
    ;; ... later ...
    (teardown-lsm-hook setup)"
  [bytecode hook & {:keys [prog-name target-btf-id]
                    :or {target-btf-id 0}
                    :as options}]
  (let [prog-fd (load-lsm-program bytecode hook options)
        link-info (attach-lsm-program prog-fd :target-btf-id target-btf-id)]
    (assoc link-info :hook hook)))

(defn teardown-lsm-hook
  "Teardown LSM hook setup.

  Parameters:
  - setup: Map returned by setup-lsm-hook with :prog-fd and :link-fd

  Example:
    (teardown-lsm-hook setup)"
  [{:keys [prog-fd link-fd]}]
  (try
    (close-lsm-link link-fd)
    (finally
      (syscall/close-fd prog-fd))))

;; ============================================================================
;; Resource Management Macros
;; ============================================================================

(defmacro with-lsm-program
  "Attach LSM program and ensure detachment after use.

  Example:
    (with-lsm-program [info (attach-lsm-program prog-fd)]
      ;; LSM program is active
      (do-work))"
  [[binding attach-expr] & body]
  `(let [~binding ~attach-expr
         info# ~binding]
     (try
       ~@body
       (finally
         (detach-lsm-program info#)))))

(defmacro with-lsm-hook
  "Load and attach LSM hook, ensure cleanup.

  Example:
    (with-lsm-hook [setup (setup-lsm-hook bytecode :file-open)]
      ;; LSM hook is active
      (do-work))"
  [[binding setup-expr] & body]
  `(let [~binding ~setup-expr
         setup# ~binding]
     (try
       ~@body
       (finally
         (teardown-lsm-hook setup#)))))

;; ============================================================================
;; LSM Utilities
;; ============================================================================

(defn lsm-available?
  "Check if LSM BPF is available on this system.

  Returns true if LSM BPF is supported, false otherwise.

  Example:
    (lsm-available?) => true"
  []
  (try
    ;; Try to load a minimal LSM program to test support
    ;; A simple program that just returns 0 (allow)
    (let [bytecode (byte-array [0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00  ; mov r0, 0
                                0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00]) ; exit
          prog-fd (load-lsm-program bytecode :file-open :license "GPL")]
      (syscall/close-fd prog-fd)
      true)
    (catch Exception e
      ;; If we get EINVAL or similar, LSM BPF is not available
      (let [msg (.getMessage e)]
        (not (or (re-find #"Invalid argument" msg)
                (re-find #"Operation not supported" msg)
                (re-find #"Function not implemented" msg)))))))

(defn list-lsm-hooks
  "List all available LSM hook points.

  Returns a vector of hook keywords.

  Example:
    (list-lsm-hooks)
    => [:file-open :file-permission :bprm-check-security ...]"
  []
  (vec (keys lsm-hooks)))

(defn get-lsm-hook-name
  "Get the LSM hook function name for a hook keyword.

  Parameters:
  - hook: Hook keyword (e.g., :file-open)

  Returns the LSM hook function name (e.g., \"file_open\")

  Example:
    (get-lsm-hook-name :file-open) => \"file_open\""
  [hook]
  (get lsm-hooks hook))

;; ============================================================================
;; LSM Hook Categories
;; ============================================================================

(def lsm-hook-categories
  {:file-system #{:file-open :file-permission :file-ioctl :file-lock :file-mprotect
                  :inode-create :inode-link :inode-unlink :inode-symlink
                  :inode-mkdir :inode-rmdir :inode-rename :inode-permission
                  :inode-setattr :inode-getattr}
   :process #{:bprm-check-security :bprm-committed-creds
              :task-kill :task-setpgid :task-getpgid
              :task-alloc :task-free}
   :credentials #{:cred-prepare}
   :network #{:socket-create :socket-bind :socket-connect
              :socket-listen :socket-accept
              :socket-sendmsg :socket-recvmsg}
   :mount #{:sb-mount :sb-umount :sb-pivotroot}})

(defn list-hooks-by-category
  "List LSM hooks by category.

  Parameters:
  - category: Category keyword (:file-system, :process, :network, etc.)

  Returns a vector of hook keywords in that category.

  Example:
    (list-hooks-by-category :file-system)
    => [:file-open :file-permission ...]"
  [category]
  (vec (get lsm-hook-categories category #{})))

(defn get-hook-category
  "Get the category for an LSM hook.

  Parameters:
  - hook: Hook keyword

  Returns the category keyword or nil if not found.

  Example:
    (get-hook-category :file-open) => :file-system"
  [hook]
  (first (for [[category hooks] lsm-hook-categories
               :when (contains? hooks hook)]
           category)))
