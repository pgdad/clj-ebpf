(ns clj-ebpf.dsl.lsm
  "High-level LSM (Linux Security Module) DSL for BPF programs.

   LSM BPF programs can be attached to security hooks to enforce
   custom security policies. They run alongside the kernel's LSM
   infrastructure (SELinux, AppArmor, etc.).

   Return values:
   - 0: Allow the operation
   - <0: Deny with error code (e.g., -EPERM, -EACCES)

   LSM programs use BTF for typed argument access.

   Example:
     (deflsm-instructions block-exec
       {:hook \"bprm_check_security\"
        :args [:bprm]}
       ;; Block execution of specific programs
       [])"
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.fentry :as fentry]))

;; ============================================================================
;; LSM Constants
;; ============================================================================

(def lsm-actions
  "LSM return values."
  {:allow 0         ; Allow the operation
   :eperm -1        ; Permission denied
   :eacces -13      ; Access denied
   :enoent -2       ; No such file
   :einval -22})    ; Invalid argument

(defn lsm-action
  "Get LSM action return value.

   Parameters:
   - action: Action keyword (:allow, :eperm, :eacces, etc.)

   Returns integer value.

   Example:
     (lsm-action :allow)   ;; => 0
     (lsm-action :eperm)   ;; => -1"
  [action]
  (or (get lsm-actions action)
      (throw (ex-info "Unknown LSM action" {:action action}))))

;; ============================================================================
;; Common LSM Hooks
;; ============================================================================

(def common-lsm-hooks
  "Common LSM hook points.

   These are frequently used security hooks that LSM BPF can attach to."
  {:bprm-check-security "Security check before program execution"
   :file-open "Security check when opening a file"
   :file-permission "Permission check for file operations"
   :file-ioctl "Security check for file ioctl"
   :file-mprotect "Security check for memory protection"
   :path-mkdir "Security check for directory creation"
   :path-rmdir "Security check for directory removal"
   :path-unlink "Security check for file deletion"
   :path-rename "Security check for file rename"
   :socket-create "Security check for socket creation"
   :socket-connect "Security check for socket connect"
   :socket-bind "Security check for socket bind"
   :socket-listen "Security check for socket listen"
   :task-alloc "Security check for task allocation"
   :task-free "Security check for task deallocation"
   :cred-alloc "Security check for credential allocation"
   :cred-free "Security check for credential deallocation"
   :inode-permission "Permission check for inode operations"
   :inode-create "Security check for inode creation"})

;; ============================================================================
;; LSM Prologue
;; ============================================================================

(defn lsm-prologue
  "Generate standard LSM program prologue.

   Saves hook arguments to callee-saved registers.

   Parameters:
   - arg-saves: Vector of [arg-index dest-reg] pairs

   Returns vector of instructions.

   Example:
     (lsm-prologue [[0 :r6] [1 :r7]])
     ;; Saves first arg to r6, second to r7"
  [arg-saves]
  (fentry/fentry-prologue arg-saves))

(defn lsm-save-args
  "Generate instructions to save LSM hook arguments.

   Parameters:
   - arg-count: Number of arguments to save (1-5)

   Returns vector of mov instructions."
  [arg-count]
  (fentry/fentry-save-args arg-count))

;; ============================================================================
;; LSM Return Patterns
;; ============================================================================

(defn lsm-allow
  "Generate instructions to allow the operation.

   Returns vector of [mov r0, 0] and exit."
  []
  [(dsl/mov :r0 0)
   (dsl/exit-insn)])

(defn lsm-deny
  "Generate instructions to deny the operation.

   Parameters:
   - errno: Error code (default :eperm = -1)

   Returns vector of instructions."
  ([]
   (lsm-deny :eperm))
  ([errno]
   [(dsl/mov :r0 (if (keyword? errno)
                  (lsm-action errno)
                  errno))
    (dsl/exit-insn)]))

(defn lsm-return
  "Generate instructions to return a specific value.

   Parameters:
   - value: Return value

   Returns vector of instructions."
  [value]
  [(dsl/mov :r0 value)
   (dsl/exit-insn)])

;; ============================================================================
;; LSM Helper Access
;; ============================================================================

(defn lsm-get-current-pid
  "Generate instructions to get current PID.

   Returns vector of instructions with PID in r0."
  []
  (fentry/fentry-log-pid))

(defn lsm-get-current-uid
  "Generate instructions to get current UID.

   Returns vector of instructions with UID in r0."
  []
  [(dsl/call 24)   ; BPF_FUNC_get_current_uid_gid
   ;; UID is in lower 32 bits, use 32-bit and with -1 (all bits)
   (dsl/alu32-imm :and :r0 -1)])  ; Truncate to 32 bits

(defn lsm-get-current-gid
  "Generate instructions to get current GID.

   Returns vector of instructions with GID in r0."
  []
  [(dsl/call 24)   ; BPF_FUNC_get_current_uid_gid
   (dsl/alu-imm :rsh :r0 32)])  ; Upper 32 bits = GID

(defn lsm-get-current-comm
  "Generate instructions to get current task comm.

   Parameters:
   - buf-reg: Register pointing to 16-byte buffer

   Returns vector of instructions."
  [buf-reg]
  (fentry/fentry-log-comm buf-reg))

;; ============================================================================
;; LSM Program Builders
;; ============================================================================

(defn build-lsm-program
  "Build a complete LSM program with standard structure.

   Parameters:
   - opts: Map with:
     :arg-saves - Vector of [arg-index dest-reg] pairs (optional)
     :body - Vector of body instructions
     :default-action - :allow or :eperm (default :allow)

   Returns assembled program bytes."
  [{:keys [arg-saves body default-action]
    :or {arg-saves [] default-action :allow}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue: save arguments
         (lsm-prologue arg-saves)
         ;; Body instructions
         body
         ;; Default action
         (if (= default-action :allow)
           (lsm-allow)
           (lsm-deny default-action))))))

(defmacro deflsm-instructions
  "Define an LSM program as a function returning instructions.

   Parameters:
   - fn-name: Name for the defined function
   - options: Map with:
     :hook - LSM hook name
     :args - Vector of argument names (for documentation)
     :arg-saves - Vector of [arg-index dest-reg] pairs (optional)
     :default-action - :allow or error code (default :allow)
   - body: Body expressions (should return vectors of instructions)

   Example:
     (deflsm-instructions check-exec
       {:hook \"bprm_check_security\"
        :args [:bprm]
        :arg-saves [[0 :r6]]
        :default-action :allow}
       [])"
  [fn-name options & body]
  (let [arg-saves (or (:arg-saves options) [])
        default-action (or (:default-action options) :allow)]
    `(defn ~fn-name
       ~(str "LSM program for hook: " (or (:hook options) "unknown") ".\n"
             "Arguments: " (or (:args options) []) "\n"
             "Default action: " default-action)
       []
       (vec (concat
             (lsm-prologue ~arg-saves)
             ~@body
             ~(if (= default-action :allow)
                `(lsm-allow)
                `(lsm-deny ~default-action)))))))

;; ============================================================================
;; Section Names and Metadata
;; ============================================================================

(defn lsm-section-name
  "Generate ELF section name for LSM program.

   Parameters:
   - hook-name: LSM hook name

   Returns section name like \"lsm/bprm_check_security\"

   Example:
     (lsm-section-name \"bprm_check_security\")
     ;; => \"lsm/bprm_check_security\""
  [hook-name]
  (str "lsm/" hook-name))

(defn make-lsm-program-info
  "Create program metadata for an LSM program.

   Parameters:
   - program-name: Name for the BPF program
   - hook-name: LSM hook to attach to
   - instructions: Program instructions

   Returns map with program metadata."
  [program-name hook-name instructions]
  {:name program-name
   :section (lsm-section-name hook-name)
   :type :lsm
   :hook hook-name
   :instructions instructions})

;; ============================================================================
;; Filter Patterns
;; ============================================================================

(defn lsm-filter-by-uid
  "Generate instructions to filter by UID.

   Parameters:
   - target-uid: UID to match
   - skip-offset: Instructions to skip if no match

   Returns vector of instructions."
  [target-uid skip-offset]
  (vec (concat
        (lsm-get-current-uid)
        [(dsl/jmp-imm :jne :r0 target-uid skip-offset)])))

(defn lsm-filter-by-pid
  "Generate instructions to filter by PID.

   Parameters:
   - target-pid: PID to match
   - skip-offset: Instructions to skip if no match

   Returns vector of instructions."
  [target-pid skip-offset]
  (fentry/fentry-filter-by-pid target-pid skip-offset))

;; ============================================================================
;; LSM Hook Information
;; ============================================================================

(defn describe-lsm-hook
  "Return information about an LSM hook.

   Parameters:
   - hook-name: Hook name (keyword or string)

   Returns map with hook information."
  [hook-name]
  (let [hook-key (if (keyword? hook-name) hook-name (keyword hook-name))]
    {:hook (name hook-key)
     :description (get common-lsm-hooks hook-key "Custom hook")
     :prog-type :lsm
     :notes ["Requires CONFIG_BPF_LSM=y"
             "Return 0 to allow, negative errno to deny"
             "Runs after other LSM modules"]}))
