(ns lsm-dsl
  "Examples demonstrating the LSM DSL.

   LSM (Linux Security Module) BPF programs enforce security policies
   by attaching to security hooks. They run alongside kernel LSM
   infrastructure (SELinux, AppArmor, etc.).

   Usage: clj -M:dev -m lsm-dsl
   Note: Requires CONFIG_BPF_LSM=y and root privileges."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.lsm :as lsm]))

;; ============================================================================
;; 1. LSM Actions Demo
;; ============================================================================

(defn demo-actions
  "Demonstrate LSM return values."
  []
  (println "\n=== LSM Actions ===")
  (println "Return 0 to allow, negative errno to deny:")
  (doseq [[k v] lsm/lsm-actions]
    (println (format "  %-8s %d" (name k) v))))

;; ============================================================================
;; 2. Common Hooks Demo
;; ============================================================================

(defn demo-hooks
  "Demonstrate common LSM hook points."
  []
  (println "\n=== Common LSM Hooks ===")
  (doseq [[hook desc] (take 10 lsm/common-lsm-hooks)]
    (println (format "  %-25s %s" (name hook) desc))))

;; ============================================================================
;; 3. Return Patterns Demo
;; ============================================================================

(defn demo-return-patterns
  "Demonstrate LSM return patterns."
  []
  (println "\n=== Return Patterns ===")

  (println "\nAllow operation:")
  (let [insns (lsm/lsm-allow)]
    (println "  Instruction count:" (count insns)))

  (println "\nDeny with EPERM:")
  (let [insns (lsm/lsm-deny :eperm)]
    (println "  Instruction count:" (count insns)))

  (println "\nDeny with EACCES:")
  (let [insns (lsm/lsm-deny :eacces)]
    (println "  Instruction count:" (count insns))))

;; ============================================================================
;; 4. Helper Functions Demo
;; ============================================================================

(defn demo-helpers
  "Demonstrate LSM helper functions."
  []
  (println "\n=== Helper Functions ===")

  (println "\nGet current PID:")
  (let [insns (lsm/lsm-get-current-pid)]
    (println "  Instruction count:" (count insns)))

  (println "\nGet current UID:")
  (let [insns (lsm/lsm-get-current-uid)]
    (println "  Instruction count:" (count insns)))

  (println "\nGet current GID:")
  (let [insns (lsm/lsm-get-current-gid)]
    (println "  Instruction count:" (count insns))))

;; ============================================================================
;; 5. Macro Demo
;; ============================================================================

(lsm/deflsm-instructions allow-all
  {:hook "bprm_check_security"
   :default-action :allow}
  [])

(lsm/deflsm-instructions deny-all
  {:hook "file_open"
   :default-action :eperm}
  [])

(defn demo-macros
  "Demonstrate deflsm-instructions macro."
  []
  (println "\n=== DSL Macros ===")

  (println "\nAllow-all program:")
  (let [insns (allow-all)]
    (println "  Instruction count:" (count insns)))

  (println "\nDeny-all program:")
  (let [insns (deny-all)]
    (println "  Instruction count:" (count insns))))

;; ============================================================================
;; 6. Section Names Demo
;; ============================================================================

(defn demo-section-names
  "Demonstrate section name generation."
  []
  (println "\n=== Section Names ===")
  (println "  bprm_check_security:" (lsm/lsm-section-name "bprm_check_security"))
  (println "  file_open:          " (lsm/lsm-section-name "file_open"))
  (println "  socket_connect:     " (lsm/lsm-section-name "socket_connect")))

;; ============================================================================
;; 7. Use Cases Demo
;; ============================================================================

(defn demo-use-cases
  "Demonstrate LSM use cases."
  []
  (println "\n=== Common Use Cases ===")

  (println "\n1. Process execution control")
  (println "   - Block execution of specific binaries")
  (println "   - Enforce process whitelisting")

  (println "\n2. File access control")
  (println "   - Block access to sensitive files")
  (println "   - Enforce read-only policies")

  (println "\n3. Network control")
  (println "   - Block socket creation")
  (println "   - Restrict network connections"))

;; ============================================================================
;; Main
;; ============================================================================

(defn -main
  "Run all LSM DSL demonstrations."
  [& args]
  (println "============================================")
  (println "  LSM (Linux Security Module) DSL Examples")
  (println "============================================")

  (demo-actions)
  (demo-hooks)
  (demo-return-patterns)
  (demo-helpers)
  (demo-macros)
  (demo-section-names)
  (demo-use-cases)

  (println "\n============================================")
  (println "  All LSM demonstrations complete!")
  (println "============================================"))
