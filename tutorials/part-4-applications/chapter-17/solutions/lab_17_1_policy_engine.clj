(ns lab-17-1-policy-engine
  "Lab 17.1: Container Policy Engine

   This solution demonstrates:
   - Per-container security policy definition
   - Policy matching and enforcement
   - Capability and syscall filtering
   - Network policy rules

   Run with: clojure -M -m lab-17-1-policy-engine test"
  (:require [clojure.string :as str]
            [clojure.set :as set]))

;;; ============================================================================
;;; Part 1: Policy Data Structures
;;; ============================================================================

(defrecord ContainerPolicy
  [container-id
   name
   allowed-syscalls      ; Set of allowed syscall numbers (nil = all)
   denied-syscalls       ; Set of denied syscall numbers
   allowed-capabilities  ; Set of allowed capabilities
   denied-capabilities   ; Set of denied capabilities
   network-policy        ; :allow-all :deny-all :allow-egress :allow-private
   file-policy           ; :read-write :read-only :deny-sensitive
   max-processes
   allow-root?
   privileged?])

(defn create-policy
  "Create a container security policy"
  [container-id name & {:keys [allowed-syscalls denied-syscalls
                               allowed-caps denied-caps
                               network file max-procs allow-root privileged]
                        :or {network :allow-all
                             file :read-write
                             max-procs 100
                             allow-root false
                             privileged false}}]
  (->ContainerPolicy
    container-id
    name
    (when allowed-syscalls (set allowed-syscalls))
    (when denied-syscalls (set denied-syscalls))
    (when allowed-caps (set allowed-caps))
    (when denied-caps (set denied-caps))
    network
    file
    max-procs
    allow-root
    privileged))

;;; ============================================================================
;;; Part 2: Policy Templates
;;; ============================================================================

(def dangerous-capabilities
  "Capabilities that enable container escape"
  #{:CAP_SYS_ADMIN :CAP_SYS_MODULE :CAP_SYS_RAWIO :CAP_NET_ADMIN
    :CAP_SYS_PTRACE :CAP_DAC_OVERRIDE :CAP_MKNOD})

(def minimal-capabilities
  "Minimal safe capabilities"
  #{:CAP_NET_BIND_SERVICE :CAP_CHOWN :CAP_SETUID :CAP_SETGID})

(def dangerous-syscalls
  "Syscalls that may indicate escape attempts"
  #{165 166 175 176 435  ; mount, umount, init_module, etc.
    101 102               ; ptrace, get/setpriority
    157 158})             ; prctl, arch_prctl

(defn restricted-policy
  "Create a highly restricted policy"
  [container-id name]
  (create-policy container-id name
                 :denied-syscalls dangerous-syscalls
                 :denied-caps dangerous-capabilities
                 :network :allow-private
                 :file :read-only
                 :max-procs 50
                 :allow-root false))

(defn standard-policy
  "Create a standard security policy"
  [container-id name]
  (create-policy container-id name
                 :denied-caps dangerous-capabilities
                 :network :allow-egress
                 :file :read-write
                 :max-procs 100
                 :allow-root false))

(defn privileged-policy
  "Create a privileged policy (use with caution)"
  [container-id name]
  (create-policy container-id name
                 :allowed-caps (set (concat minimal-capabilities dangerous-capabilities))
                 :network :allow-all
                 :file :read-write
                 :max-procs 500
                 :allow-root true
                 :privileged true))

;;; ============================================================================
;;; Part 3: Policy Store
;;; ============================================================================

(def policy-store
  "Store of container policies"
  (atom {}))

(def default-policy
  "Default policy for unregistered containers"
  (atom (standard-policy 0 "default")))

(defn register-policy!
  "Register a container policy"
  [policy]
  (swap! policy-store assoc (:container-id policy) policy))

(defn get-policy
  "Get policy for a container"
  [container-id]
  (get @policy-store container-id @default-policy))

(defn remove-policy!
  "Remove a container policy"
  [container-id]
  (swap! policy-store dissoc container-id))

(defn set-default-policy!
  "Set the default policy"
  [policy]
  (reset! default-policy policy))

(defn list-policies
  "List all registered policies"
  []
  (vals @policy-store))

(defn clear-policies!
  "Clear all policies"
  []
  (reset! policy-store {}))

;;; ============================================================================
;;; Part 4: Policy Enforcement
;;; ============================================================================

(defn check-syscall
  "Check if syscall is allowed by policy"
  [policy syscall-nr]
  (cond
    ;; Explicitly denied
    (and (:denied-syscalls policy)
         (contains? (:denied-syscalls policy) syscall-nr))
    {:allowed false :reason :denied-syscall}

    ;; Allowed list exists and syscall not in it
    (and (:allowed-syscalls policy)
         (not (contains? (:allowed-syscalls policy) syscall-nr)))
    {:allowed false :reason :not-allowed-syscall}

    :else
    {:allowed true}))

(defn check-capability
  "Check if capability is allowed by policy"
  [policy capability]
  (cond
    ;; Privileged containers allow all
    (:privileged? policy)
    {:allowed true}

    ;; Explicitly denied
    (and (:denied-capabilities policy)
         (contains? (:denied-capabilities policy) capability))
    {:allowed false :reason :denied-capability}

    ;; Allowed list exists and cap not in it
    (and (:allowed-capabilities policy)
         (not (contains? (:allowed-capabilities policy) capability)))
    {:allowed false :reason :not-allowed-capability}

    ;; Check dangerous capabilities
    (contains? dangerous-capabilities capability)
    {:allowed false :reason :dangerous-capability}

    :else
    {:allowed true}))

(defn check-network
  "Check if network access is allowed"
  [policy dst-ip dst-port]
  (case (:network-policy policy)
    :allow-all {:allowed true}
    :deny-all {:allowed false :reason :network-denied}
    :allow-egress {:allowed true}
    :allow-private
    (let [first-octet (first dst-ip)]
      (if (or (= first-octet 10)
              (= first-octet 127)
              (and (= first-octet 172) (<= 16 (second dst-ip) 31))
              (and (= first-octet 192) (= (second dst-ip) 168)))
        {:allowed true}
        {:allowed false :reason :public-network-denied}))
    {:allowed true}))

(defn check-file-access
  "Check if file access is allowed"
  [policy file-path is-write?]
  (let [sensitive-paths #{"/etc/shadow" "/etc/passwd" "/proc" "/sys"
                          "/var/run/docker.sock" "/.dockerenv"}]
    (case (:file-policy policy)
      :read-write {:allowed true}
      :read-only (if is-write?
                   {:allowed false :reason :write-denied}
                   {:allowed true})
      :deny-sensitive
      (if (some #(str/starts-with? file-path %) sensitive-paths)
        {:allowed false :reason :sensitive-path}
        {:allowed true})
      {:allowed true})))

(defn check-process-limit
  "Check if process limit is exceeded"
  [policy current-count]
  (if (>= current-count (:max-processes policy))
    {:allowed false :reason :process-limit-exceeded}
    {:allowed true}))

(defn check-root-execution
  "Check if root execution is allowed"
  [policy uid]
  (if (and (zero? uid) (not (:allow-root? policy)))
    {:allowed false :reason :root-denied}
    {:allowed true}))

;;; ============================================================================
;;; Part 5: Policy Validation
;;; ============================================================================

(defn validate-policy
  "Validate a policy for consistency"
  [policy]
  (let [errors (atom [])]
    ;; Check for conflicting syscall rules
    (when (and (:allowed-syscalls policy) (:denied-syscalls policy))
      (let [overlap (set/intersection (:allowed-syscalls policy)
                                       (:denied-syscalls policy))]
        (when (seq overlap)
          (swap! errors conj {:type :syscall-conflict :syscalls overlap}))))

    ;; Check for conflicting capability rules
    (when (and (:allowed-capabilities policy) (:denied-capabilities policy))
      (let [overlap (set/intersection (:allowed-capabilities policy)
                                       (:denied-capabilities policy))]
        (when (seq overlap)
          (swap! errors conj {:type :capability-conflict :capabilities overlap}))))

    ;; Warn about dangerous configurations
    (when (and (:privileged? policy) (not (:allow-root? policy)))
      (swap! errors conj {:type :warning :message "Privileged without root"}))

    (when (and (= :deny-all (:network-policy policy))
               (= :read-only (:file-policy policy)))
      (swap! errors conj {:type :warning :message "Very restrictive policy"}))

    {:valid (empty? (filter #(not= :warning (:type %)) @errors))
     :errors @errors}))

;;; ============================================================================
;;; Part 6: Policy Serialization
;;; ============================================================================

(defn policy->map
  "Convert policy to map for serialization"
  [policy]
  {:container-id (:container-id policy)
   :name (:name policy)
   :allowed-syscalls (vec (or (:allowed-syscalls policy) []))
   :denied-syscalls (vec (or (:denied-syscalls policy) []))
   :allowed-capabilities (vec (map name (or (:allowed-capabilities policy) [])))
   :denied-capabilities (vec (map name (or (:denied-capabilities policy) [])))
   :network-policy (:network-policy policy)
   :file-policy (:file-policy policy)
   :max-processes (:max-processes policy)
   :allow-root (:allow-root? policy)
   :privileged (:privileged? policy)})

(defn map->policy
  "Create policy from map"
  [m]
  (create-policy
    (:container-id m)
    (:name m)
    :allowed-syscalls (when (seq (:allowed-syscalls m)) (:allowed-syscalls m))
    :denied-syscalls (when (seq (:denied-syscalls m)) (:denied-syscalls m))
    :allowed-caps (when (seq (:allowed-capabilities m))
                    (map keyword (:allowed-capabilities m)))
    :denied-caps (when (seq (:denied-capabilities m))
                   (map keyword (:denied-capabilities m)))
    :network (:network-policy m)
    :file (:file-policy m)
    :max-procs (:max-processes m)
    :allow-root (:allow-root m)
    :privileged (:privileged m)))

;;; ============================================================================
;;; Part 7: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 17.1 Tests ===\n")

  ;; Test 1: Policy creation
  (println "Test 1: Policy Creation")
  (let [policy (create-policy 1234 "test" :network :deny-all :max-procs 50)]
    (assert (= 1234 (:container-id policy)) "container id")
    (assert (= :deny-all (:network-policy policy)) "network policy")
    (assert (= 50 (:max-processes policy)) "max processes"))
  (println "  Policy created correctly")
  (println "  PASSED\n")

  ;; Test 2: Policy templates
  (println "Test 2: Policy Templates")
  (let [restricted (restricted-policy 1 "r")
        standard (standard-policy 2 "s")
        privileged (privileged-policy 3 "p")]
    (assert (= :allow-private (:network-policy restricted)) "restricted network")
    (assert (= :allow-egress (:network-policy standard)) "standard network")
    (assert (:privileged? privileged) "privileged flag"))
  (println "  Policy templates work correctly")
  (println "  PASSED\n")

  ;; Test 3: Syscall checking
  (println "Test 3: Syscall Checking")
  (let [policy (create-policy 1 "test" :denied-syscalls #{165 166})]
    (assert (not (:allowed (check-syscall policy 165))) "denied syscall blocked")
    (assert (:allowed (check-syscall policy 0)) "other syscall allowed"))
  (println "  Syscall checking works correctly")
  (println "  PASSED\n")

  ;; Test 4: Capability checking
  (println "Test 4: Capability Checking")
  (let [policy (restricted-policy 1 "test")]
    (assert (not (:allowed (check-capability policy :CAP_SYS_ADMIN)))
            "dangerous cap blocked")
    (assert (:allowed (check-capability policy :CAP_CHOWN))
            "safe cap allowed"))
  (println "  Capability checking works correctly")
  (println "  PASSED\n")

  ;; Test 5: Network policy
  (println "Test 5: Network Policy")
  (let [policy (create-policy 1 "test" :network :allow-private)]
    (assert (:allowed (check-network policy [10 0 0 1] 80)) "private allowed")
    (assert (:allowed (check-network policy [192 168 1 1] 443)) "private allowed")
    (assert (not (:allowed (check-network policy [8 8 8 8] 53))) "public blocked"))
  (println "  Network policy works correctly")
  (println "  PASSED\n")

  ;; Test 6: File policy
  (println "Test 6: File Policy")
  (let [policy (create-policy 1 "test" :file :deny-sensitive)]
    (assert (:allowed (check-file-access policy "/home/user/file" true)) "normal allowed")
    (assert (not (:allowed (check-file-access policy "/etc/shadow" false))) "shadow blocked"))
  (println "  File policy works correctly")
  (println "  PASSED\n")

  ;; Test 7: Policy store
  (println "Test 7: Policy Store")
  (clear-policies!)
  (let [p1 (create-policy 100 "container1")
        p2 (create-policy 200 "container2")]
    (register-policy! p1)
    (register-policy! p2)
    (assert (= "container1" (:name (get-policy 100))) "policy 1 found")
    (assert (= "container2" (:name (get-policy 200))) "policy 2 found")
    (assert (= "default" (:name (get-policy 999))) "default returned"))
  (println "  Policy store works correctly")
  (println "  PASSED\n")

  ;; Test 8: Policy validation
  (println "Test 8: Policy Validation")
  (let [valid-policy (standard-policy 1 "valid")
        invalid-policy (create-policy 2 "invalid"
                                      :allowed-syscalls #{0 1 2}
                                      :denied-syscalls #{1 2 3})]
    (assert (:valid (validate-policy valid-policy)) "valid policy")
    (assert (not (:valid (validate-policy invalid-policy))) "invalid policy"))
  (println "  Policy validation works correctly")
  (println "  PASSED\n")

  ;; Test 9: Process limits
  (println "Test 9: Process Limits")
  (let [policy (create-policy 1 "test" :max-procs 10)]
    (assert (:allowed (check-process-limit policy 5)) "under limit")
    (assert (not (:allowed (check-process-limit policy 10))) "at limit")
    (assert (not (:allowed (check-process-limit policy 15))) "over limit"))
  (println "  Process limits work correctly")
  (println "  PASSED\n")

  ;; Test 10: Root checking
  (println "Test 10: Root Execution Checking")
  (let [no-root-policy (create-policy 1 "test" :allow-root false)
        root-policy (create-policy 2 "test" :allow-root true)]
    (assert (not (:allowed (check-root-execution no-root-policy 0))) "root blocked")
    (assert (:allowed (check-root-execution no-root-policy 1000)) "non-root allowed")
    (assert (:allowed (check-root-execution root-policy 0)) "root allowed when configured"))
  (println "  Root checking works correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 8: Demo
;;; ============================================================================

(defn run-demo
  "Run demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 17.1: Container Policy Engine")
  (println (str/join "" (repeat 60 "=")) "\n")

  (clear-policies!)

  ;; Register some policies
  (println "=== Registering Container Policies ===\n")

  (register-policy! (restricted-policy 1001 "nginx-frontend"))
  (register-policy! (standard-policy 1002 "api-backend"))
  (register-policy! (privileged-policy 1003 "monitoring-agent"))

  (doseq [p (list-policies)]
    (println (format "Container: %s (ID: %d)" (:name p) (:container-id p)))
    (println (format "  Network: %s, File: %s, Max Procs: %d"
                     (name (:network-policy p))
                     (name (:file-policy p))
                     (:max-processes p)))
    (println (format "  Allow Root: %s, Privileged: %s"
                     (:allow-root? p) (:privileged? p)))
    (println))

  ;; Test enforcement
  (println "=== Policy Enforcement Examples ===\n")

  (let [tests [{:container 1001 :action "CAP_SYS_ADMIN"
                :check #(check-capability (get-policy 1001) :CAP_SYS_ADMIN)}
               {:container 1001 :action "Connect to 8.8.8.8:53"
                :check #(check-network (get-policy 1001) [8 8 8 8] 53)}
               {:container 1002 :action "Connect to 8.8.8.8:53"
                :check #(check-network (get-policy 1002) [8 8 8 8] 53)}
               {:container 1002 :action "Write to /etc/shadow"
                :check #(check-file-access (get-policy 1002) "/etc/shadow" true)}
               {:container 1003 :action "CAP_SYS_ADMIN"
                :check #(check-capability (get-policy 1003) :CAP_SYS_ADMIN)}]]

    (doseq [{:keys [container action check]} tests]
      (let [result (check)
            status (if (:allowed result) "ALLOWED" "BLOCKED")]
        (println (format "Container %d: %s -> %s"
                         container action status))
        (when-not (:allowed result)
          (println (format "  Reason: %s" (name (:reason result)))))))))

;;; ============================================================================
;;; Part 9: Main
;;; ============================================================================

(defn -main [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      (do
        (println "Usage: clojure -M -m lab-17-1-policy-engine <command>")
        (println "Commands:")
        (println "  test  - Run tests")
        (println "  demo  - Run demonstration")))))
