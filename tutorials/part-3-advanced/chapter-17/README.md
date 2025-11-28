# Chapter 17: Security and Best Practices

**Duration**: 3-4 hours | **Difficulty**: Advanced

This chapter covers security considerations, privilege management, and best practices for production BPF deployments.

## Learning Objectives

By the end of this chapter, you will:
- Understand BPF security model and capabilities
- Implement least-privilege BPF deployments
- Secure BPF maps and prevent data leaks
- Handle sensitive data safely
- Follow production hardening guidelines
- Audit and monitor BPF programs

## Prerequisites

- Completed Chapters 10-16
- Understanding of Linux capabilities
- Familiarity with security concepts

---

## 17.1 BPF Security Model

### The Verifier: First Line of Defense

The BPF verifier enforces safety properties before any program runs:

1. **Memory Safety**: All memory accesses are bounds-checked
2. **Termination**: Programs must terminate (bounded loops)
3. **Type Safety**: Register types are tracked and validated
4. **Privilege Checks**: Helpers require appropriate capabilities

```clojure
;; The verifier rejects unsafe programs
(def unsafe-program
  [;; This will be rejected: out-of-bounds access
   [(bpf/load-mem :dw :r1 :r2 0)]  ; No bounds check!
   [(bpf/exit)]])

;; Safe version with bounds check
(def safe-program
  [[(bpf/load-ctx :dw :r2 0)]      ; data
   [(bpf/load-ctx :dw :r3 8)]      ; data_end
   [(bpf/mov-reg :r4 :r2)]
   [(bpf/add :r4 8)]
   [(bpf/jmp-reg :jgt :r4 :r3 :exit)]  ; Bounds check
   [(bpf/load-mem :dw :r1 :r2 0)]      ; Safe access
   [:exit]
   [(bpf/exit)]])
```

### Capability Requirements

Different BPF operations require different capabilities:

| Capability | Operations |
|------------|------------|
| CAP_BPF | Load programs, create maps |
| CAP_PERFMON | Attach to tracepoints, kprobes |
| CAP_NET_ADMIN | XDP, TC, socket filtering |
| CAP_SYS_ADMIN | Older kernels (pre-5.8) |

```clojure
;; Check capabilities before loading
(defn check-bpf-capabilities []
  (let [caps (get-process-capabilities)]
    {:can-load-programs (or (contains? caps :cap_bpf)
                            (contains? caps :cap_sys_admin))
     :can-attach-kprobes (or (contains? caps :cap_perfmon)
                             (contains? caps :cap_sys_admin))
     :can-attach-xdp (or (contains? caps :cap_net_admin)
                         (contains? caps :cap_sys_admin))}))
```

---

## 17.2 Least Privilege Principle

### Dropping Privileges After Loading

```clojure
(require '[clj-ebpf.core :as bpf])

(defn load-with-minimal-privileges []
  ;; 1. Start with required capabilities
  (assert (has-capability? :cap_bpf) "CAP_BPF required")

  ;; 2. Load programs and create maps
  (let [program (bpf/load-program my-bpf-program)
        maps (bpf/create-maps my-map-specs)]

    ;; 3. Pin to filesystem for persistence
    (bpf/pin-program program "/sys/fs/bpf/myapp/prog")
    (doseq [[name map-ref] maps]
      (bpf/pin-map map-ref (str "/sys/fs/bpf/myapp/" name)))

    ;; 4. Drop capabilities - no longer needed
    (drop-capabilities! [:cap_bpf :cap_perfmon])

    ;; 5. Return handles for unprivileged access
    {:program program :maps maps}))
```

### Unprivileged Map Access

```clojure
;; After pinning, maps can be accessed without CAP_BPF
(defn access-pinned-maps []
  ;; Open pinned map (no special privileges needed)
  (let [stats-map (bpf/open-pinned-map "/sys/fs/bpf/myapp/stats")]

    ;; Read operations work
    (println "Stats:" (bpf/map-lookup stats-map :total-packets))

    ;; Write operations may be restricted by map flags
    ;; (bpf/map-update stats-map :key :value)

    stats-map))
```

### Systemd Integration

```ini
# /etc/systemd/system/my-bpf-app.service
[Unit]
Description=My BPF Application
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/my-bpf-app

# Minimal capabilities
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/sys/fs/bpf

[Install]
WantedBy=multi-user.target
```

---

## 17.3 Securing BPF Maps

### Map Access Control

```clojure
;; Create map with restricted access
(def secure-map
  {:type :hash
   :key-type :u64
   :value-type :u64
   :max-entries 1000
   :flags #{:BPF_F_RDONLY_PROG   ; Programs can only read
            :BPF_F_WRONLY}})     ; Userspace can only write

;; Freeze map after initialization
(defn freeze-config-map [map-ref]
  "Make map read-only after initial configuration"
  (bpf/map-freeze map-ref))

;; Example: Configuration that can't be modified at runtime
(defn setup-config []
  (let [config-map (bpf/create-map config-spec)]
    ;; Initialize config
    (bpf/map-update config-map :max-connections 10000)
    (bpf/map-update config-map :rate-limit 1000)

    ;; Freeze - no more updates allowed
    (freeze-config-map config-map)

    config-map))
```

### Preventing Information Leaks

```clojure
;; Sensitive data handling
(defn handle-sensitive-event [event]
  (let [sanitized-event
        (-> event
            ;; Mask sensitive fields
            (update :source-ip mask-ip-address)
            (update :user-id hash-user-id)
            ;; Remove unnecessary data
            (dissoc :raw-payload :credentials))]

    ;; Log sanitized version only
    (log/info "Event:" sanitized-event)))

(defn mask-ip-address [ip]
  "Mask last octet for privacy"
  (let [parts (clojure.string/split ip #"\.")]
    (str (clojure.string/join "." (take 3 parts)) ".0")))

(defn hash-user-id [user-id]
  "One-way hash for pseudonymization"
  (-> user-id
      str
      (.getBytes)
      (java.security.MessageDigest/getInstance "SHA-256")
      (.digest)
      (bytes->hex)
      (subs 0 16)))
```

### Map Content Sanitization

```clojure
(defn sanitize-map-dump [map-ref sensitive-keys]
  "Dump map contents with sensitive fields redacted"
  (into {}
    (for [[k v] (bpf/map-get-all map-ref)]
      [k (reduce
           (fn [entry key]
             (if (contains? entry key)
               (assoc entry key "[REDACTED]")
               entry))
           v
           sensitive-keys)])))

;; Usage
(sanitize-map-dump connection-map [:password :token :api-key])
```

---

## 17.4 Safe Data Handling

### Input Validation

```clojure
;; Validate data before writing to BPF maps
(defn validate-config [config]
  (let [errors (atom [])]
    ;; Check required fields
    (when-not (:max-connections config)
      (swap! errors conj "max-connections required"))

    ;; Check value ranges
    (when (and (:max-connections config)
               (or (< (:max-connections config) 1)
                   (> (:max-connections config) 1000000)))
      (swap! errors conj "max-connections must be 1-1000000"))

    ;; Check types
    (when (and (:rate-limit config)
               (not (integer? (:rate-limit config))))
      (swap! errors conj "rate-limit must be integer"))

    (if (empty? @errors)
      {:valid true :config config}
      {:valid false :errors @errors})))

(defn safe-update-config [map-ref config]
  (let [{:keys [valid errors config]} (validate-config config)]
    (if valid
      (do
        (doseq [[k v] config]
          (bpf/map-update map-ref k v))
        {:success true})
      {:success false :errors errors})))
```

### Output Sanitization

```clojure
;; Sanitize BPF map output before external use
(def sensitive-patterns
  [#"password[=:]\S+"
   #"token[=:]\S+"
   #"api[_-]?key[=:]\S+"
   #"\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}"])  ; Credit card

(defn sanitize-string [s]
  (reduce
    (fn [text pattern]
      (clojure.string/replace text pattern "[REDACTED]"))
    s
    sensitive-patterns))

(defn sanitize-event [event]
  (clojure.walk/postwalk
    (fn [x]
      (if (string? x)
        (sanitize-string x)
        x))
    event))
```

### Secure Serialization

```clojure
;; Avoid deserializing untrusted data
(defn safe-deserialize [bytes expected-schema]
  (try
    (let [data (deserialize bytes)]
      ;; Validate against schema
      (if (valid-schema? data expected-schema)
        {:success true :data data}
        {:success false :error "Schema validation failed"}))
    (catch Exception e
      {:success false :error (.getMessage e)})))

;; Use structured serialization
(defn serialize-event [event]
  ;; Use protocol buffers or similar, not eval-able formats
  (-> event
      (select-keys [:timestamp :event-type :source :data])
      (json/write-str)))
```

---

## 17.5 Privilege Escalation Prevention

### Sandboxing BPF Operations

```clojure
;; Restrict what BPF programs can do
(def allowed-helpers
  #{:map_lookup_elem
    :map_update_elem
    :ktime_get_ns
    :get_current_pid_tgid})

(defn validate-program-helpers [program]
  "Ensure program only uses allowed helpers"
  (let [used-helpers (extract-helper-calls program)]
    (if (every? allowed-helpers used-helpers)
      {:valid true}
      {:valid false
       :disallowed (clojure.set/difference used-helpers allowed-helpers)})))

;; Restrict map types
(def allowed-map-types
  #{:array :hash :percpu_array :percpu_hash})

(defn validate-map-types [map-specs]
  (every? #(contains? allowed-map-types (:type %)) map-specs))
```

### Runtime Monitoring

```clojure
(defn setup-bpf-audit []
  "Monitor BPF operations for suspicious activity"
  (let [audit-events (atom [])
        suspicious-threshold 100]

    ;; Track program loads
    (add-bpf-audit-hook :program-load
      (fn [event]
        (swap! audit-events conj
               {:type :program-load
                :timestamp (System/currentTimeMillis)
                :details event})

        ;; Alert on excessive program loads
        (when (> (count (filter #(= :program-load (:type %))
                                @audit-events))
                 suspicious-threshold)
          (alert! "Excessive BPF program loads detected"))))

    ;; Track map creations
    (add-bpf-audit-hook :map-create
      (fn [event]
        (swap! audit-events conj
               {:type :map-create
                :timestamp (System/currentTimeMillis)
                :details event})))

    {:events audit-events
     :stop (fn [] (remove-all-audit-hooks))}))
```

---

## 17.6 Production Hardening

### Error Handling

```clojure
;; Never expose internal errors to users
(defn safe-bpf-operation [operation]
  (try
    {:success true :result (operation)}
    (catch SecurityException e
      (log/error "Security violation:" (.getMessage e))
      {:success false :error "Permission denied"})
    (catch Exception e
      (log/error "BPF operation failed:" e)
      {:success false :error "Operation failed"})))

;; Structured error responses
(defn format-error-response [error-code]
  (case error-code
    :permission-denied
    {:code 403 :message "Insufficient permissions"}

    :invalid-input
    {:code 400 :message "Invalid input parameters"}

    :resource-exhausted
    {:code 429 :message "Resource limit exceeded"}

    ;; Default - don't leak details
    {:code 500 :message "Internal error"}))
```

### Resource Limits

```clojure
(def resource-limits
  {:max-maps 100
   :max-programs 50
   :max-map-entries 1000000
   :max-event-rate 100000})  ; per second

(defn enforce-limits [operation resource-type]
  (let [current (get-current-usage resource-type)
        limit (get resource-limits resource-type)]
    (if (< current limit)
      (operation)
      (throw (ex-info "Resource limit exceeded"
                      {:resource resource-type
                       :current current
                       :limit limit})))))

(defn create-map-with-limits [spec]
  (enforce-limits
    #(bpf/create-map spec)
    :max-maps))
```

### Graceful Degradation

```clojure
(defn resilient-bpf-load []
  "Load BPF with fallback options"
  (try
    ;; Try full-featured version
    (bpf/load-program advanced-program)
    (catch Exception e
      (log/warn "Advanced program failed, trying basic:" e)
      (try
        ;; Fall back to simpler version
        (bpf/load-program basic-program)
        (catch Exception e
          (log/error "BPF load failed completely:" e)
          ;; Return stub that logs but doesn't process
          (create-stub-program))))))

(defn create-stub-program []
  "Stub that maintains interface but does nothing"
  {:type :stub
   :process (fn [event] (log/debug "Stub received:" event))
   :stats (fn [] {:events 0 :status :degraded})})
```

---

## 17.7 Audit and Compliance

### Logging Best Practices

```clojure
(defn create-audit-logger []
  {:log-event
   (fn [event-type details]
     (let [entry {:timestamp (java.time.Instant/now)
                  :type event-type
                  :user (get-current-user)
                  :details details}]
       ;; Write to secure audit log
       (audit-log/write entry)
       ;; Send to SIEM if configured
       (when (siem-configured?)
         (siem/send entry))))

   :log-access
   (fn [resource action result]
     (audit-log/write
       {:timestamp (java.time.Instant/now)
        :type :access
        :resource resource
        :action action
        :result result
        :user (get-current-user)}))})

;; Usage
(defn audited-map-update [map-ref key value]
  (let [result (safe-bpf-operation
                 #(bpf/map-update map-ref key value))]
    ((:log-access audit-logger)
     (str "map:" (:name map-ref))
     :update
     (:success result))
    result))
```

### Compliance Checks

```clojure
(defn compliance-check []
  "Run compliance checks on BPF deployment"
  (let [checks
        [{:name "No root programs"
          :check #(empty? (filter root-owned? (list-bpf-programs)))
          :severity :high}

         {:name "All maps have limits"
          :check #(every? has-max-entries? (list-bpf-maps))
          :severity :medium}

         {:name "Audit logging enabled"
          :check #(audit-logging-enabled?)
          :severity :high}

         {:name "Capabilities minimal"
          :check #(<= (count (get-process-capabilities)) 3)
          :severity :medium}]]

    (for [{:keys [name check severity]} checks]
      {:check name
       :passed (try (check) (catch Exception _ false))
       :severity severity})))

(defn print-compliance-report []
  (println "\n=== BPF Compliance Report ===\n")
  (doseq [{:keys [check passed severity]} (compliance-check)]
    (println (format "[%s] %s - %s"
                     (if passed "PASS" "FAIL")
                     check
                     (name severity)))))
```

---

## 17.8 Security Checklist

### Pre-Deployment

- [ ] Programs verified to use only allowed helpers
- [ ] Maps have appropriate access flags
- [ ] Input validation implemented
- [ ] Output sanitization in place
- [ ] Resource limits configured
- [ ] Capability requirements minimized
- [ ] Audit logging enabled

### Runtime

- [ ] Monitor for unusual BPF activity
- [ ] Track resource usage
- [ ] Log all configuration changes
- [ ] Alert on security violations
- [ ] Regular compliance checks

### Incident Response

- [ ] Ability to disable programs quickly
- [ ] Audit trail preservation
- [ ] Rollback capability
- [ ] Forensic data collection

---

## Labs

### Lab 17.1: Secure BPF Deployment

Implement a secure BPF loader with capability management and audit logging.

[Go to Lab 17.1](labs/lab-17-1-secure-deployment.md)

### Lab 17.2: Data Sanitization Pipeline

Build a pipeline that sanitizes sensitive data from BPF events.

[Go to Lab 17.2](labs/lab-17-2-data-sanitization.md)

### Lab 17.3: Security Audit Framework

Create a framework for auditing BPF programs and maps.

[Go to Lab 17.3](labs/lab-17-3-audit-framework.md)

---

## Key Takeaways

1. **Verifier Is Essential**: It prevents most safety issues, but understand its limits
2. **Least Privilege**: Only request capabilities you need, drop them when done
3. **Map Security**: Use flags to restrict access, freeze when appropriate
4. **Data Handling**: Validate inputs, sanitize outputs, protect sensitive data
5. **Monitoring**: Log operations, detect anomalies, maintain audit trails
6. **Defense in Depth**: Multiple layers of security, graceful degradation

## References

- [BPF Security Documentation](https://www.kernel.org/doc/html/latest/bpf/bpf_lsm.html)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [BPF Design Q&A](https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html)
