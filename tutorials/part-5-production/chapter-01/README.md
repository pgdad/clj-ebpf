# Chapter 23: Production Deployment

## Overview

Learn how to deploy eBPF applications to production environments safely and reliably. This chapter covers deployment strategies, monitoring, resource management, and security considerations for production eBPF systems.

**Topics**:
- Deployment strategies and rollback procedures
- Monitoring and observability
- Resource management
- Security hardening
- Configuration management
- High availability patterns

## 23.1 Deployment Strategies

### Canary Deployments for BPF Programs

```clojure
(ns production.deployment
  (:require [clj-ebpf.core :as bpf]))

(defn canary-deploy
  "Deploy new BPF program version to subset of hosts"
  [program-new program-old canary-percentage]
  (let [total-hosts (count (get-all-hosts))
        canary-count (int (* total-hosts (/ canary-percentage 100)))]

    (println (format "Starting canary deployment to %d/%d hosts"
                    canary-count total-hosts))

    ;; Deploy to canary hosts
    (let [canary-hosts (take canary-count (get-all-hosts))]
      (doseq [host canary-hosts]
        (deploy-to-host host program-new)))

    ;; Monitor canary hosts
    (println "Monitoring canary hosts for 15 minutes...")
    (Thread/sleep (* 15 60 1000))

    ;; Check health metrics
    (let [health (check-canary-health)]
      (if (:healthy health)
        (do
          (println "✅ Canary healthy, rolling out to all hosts")
          (rollout-to-all-hosts program-new))
        (do
          (println "❌ Canary unhealthy, rolling back")
          (rollback-canary canary-hosts program-old))))))

(defn deploy-to-host [host program]
  "Deploy BPF program to specific host"
  (try
    ;; Load program
    (let [loaded-prog (bpf/load-program program (:type program))]

      ;; Attach to hooks
      (doseq [attach-point (:attach-points program)]
        (attach-program loaded-prog attach-point))

      ;; Verify program is running
      (when-not (verify-program-running loaded-prog)
        (throw (ex-info "Program failed to start" {:host host})))

      ;; Pin program for persistence
      (bpf/pin-program loaded-prog (str "/sys/fs/bpf/" (:name program)))

      {:status :success :host host})
    (catch Exception e
      {:status :failed :host host :error (.getMessage e)})))

(defn check-canary-health []
  "Check health metrics of canary deployment"
  (let [metrics (collect-metrics)
        baseline (get-baseline-metrics)]

    {:healthy (and
                ;; No program crashes
                (zero? (:program-failures metrics))

                ;; Overhead within acceptable range
                (< (:cpu-overhead metrics) 5.0)
                (< (:memory-overhead metrics) (* 1024 1024 100))  ; 100MB

                ;; Error rate not increased
                (<= (:error-rate metrics)
                   (* 1.1 (:error-rate baseline)))

                ;; Latency not degraded
                (<= (:p99-latency metrics)
                   (* 1.2 (:p99-latency baseline))))
     :metrics metrics
     :baseline baseline}))
```

### Blue-Green Deployment

```clojure
(defn blue-green-deploy [program-new]
  "Deploy new version alongside old, switch traffic atomically"
  (let [blue-version (get-current-version)
        green-version program-new]

    ;; Deploy green version (inactive)
    (println "Deploying green version...")
    (deploy-version green-version :inactive)

    ;; Health check green
    (println "Health checking green version...")
    (when-not (health-check green-version)
      (cleanup-version green-version)
      (throw (ex-info "Green version failed health check" {})))

    ;; Switch traffic to green
    (println "Switching traffic to green...")
    (switch-traffic blue-version green-version)

    ;; Monitor for issues
    (Thread/sleep 60000)  ; 1 minute

    ;; If healthy, cleanup blue
    (if (version-healthy? green-version)
      (do
        (println "✅ Deployment successful")
        (cleanup-version blue-version))
      (do
        (println "❌ Issues detected, rolling back")
        (switch-traffic green-version blue-version)
        (cleanup-version green-version)))))

(defn switch-traffic [from-version to-version]
  "Atomically switch traffic from one version to another"
  ;; Update configuration map to point to new program
  (bpf/map-update! config-map :active-version (:id to-version))

  ;; Wait for all in-flight requests to complete
  (Thread/sleep 1000))
```

### Version Management

```clojure
(defrecord ProgramVersion
  [id :u32
   name [64 :u8]
   commit-hash [40 :u8]
   deployed-at :u64
   status :u8])  ; ACTIVE, INACTIVE, DEPRECATED

(def version-registry
  "Track deployed program versions"
  {:type :hash
   :key-type :u32      ; Version ID
   :value-type :struct ; ProgramVersion
   :max-entries 100})

(defn register-version [program commit-hash]
  "Register new program version"
  (let [version-id (generate-version-id)
        version {:id version-id
                 :name (:name program)
                 :commit-hash commit-hash
                 :deployed-at (System/currentTimeMillis)
                 :status :inactive}]

    (bpf/map-update! version-registry version-id version)
    version-id))

(defn rollback-to-version [version-id]
  "Rollback to previous version"
  (let [version (bpf/map-lookup version-registry version-id)]
    (when-not version
      (throw (ex-info "Version not found" {:version-id version-id})))

    (println (format "Rolling back to version %s (commit: %s)"
                    (:name version)
                    (:commit-hash version)))

    ;; Load program from artifact storage
    (let [program (load-program-artifact version-id)]
      (deploy-version program :active))))
```

## 23.2 Monitoring and Observability

### Program Health Monitoring

```clojure
(def program-stats
  "Track program execution statistics"
  {:type :hash
   :key-type :u32      ; Program ID
   :value-type :struct ; {run_count, error_count, avg_duration}
   :max-entries 100})

(defn monitor-program-health []
  "Continuously monitor BPF program health"
  (loop []
    (let [stats (bpf/map-get-all program-stats)]

      (doseq [[prog-id prog-stats] stats]
        (let [error-rate (/ (:error-count prog-stats)
                           (max 1 (:run-count prog-stats)))]

          ;; Alert on high error rate
          (when (> error-rate 0.01)  ; 1%
            (alert-program-errors prog-id error-rate))

          ;; Alert on slow execution
          (when (> (:avg-duration prog-stats) 1000000)  ; 1ms
            (alert-slow-program prog-id (:avg-duration prog-stats)))))

      ;; Export metrics to Prometheus
      (export-metrics-prometheus stats))

    (Thread/sleep 10000)  ; Check every 10 seconds
    (recur)))

(defn export-metrics-prometheus [stats]
  "Export BPF program metrics in Prometheus format"
  (doseq [[prog-id prog-stats] stats]
    (prometheus/gauge "bpf_program_runs_total"
                     {:program_id prog-id}
                     (:run-count prog-stats))

    (prometheus/gauge "bpf_program_errors_total"
                     {:program_id prog-id}
                     (:error-count prog-stats))

    (prometheus/gauge "bpf_program_duration_microseconds"
                     {:program_id prog-id}
                     (:avg-duration prog-stats))))
```

### Log Aggregation

```clojure
(defn setup-program-logging [program]
  "Setup structured logging for BPF program"
  (let [log-buffer (bpf/create-ringbuf-map
                    {:max-entries (* 1 1024 1024)})]  ; 1MB

    ;; Consume logs from ring buffer
    (future
      (bpf/consume-ringbuf log-buffer
        (fn [event]
          (let [log-entry (parse-log-entry event)]

            ;; Forward to centralized logging
            (forward-to-loki log-entry)

            ;; Alert on errors
            (when (= (:level log-entry) :error)
              (alert-program-error log-entry))))))

    log-buffer))

(defn parse-log-entry [event-bytes]
  "Parse structured log entry"
  {:timestamp (read-u64 event-bytes 0)
   :level (decode-log-level (read-u8 event-bytes 8))
   :program-id (read-u32 event-bytes 9)
   :message (read-string event-bytes 13 256)
   :metadata (parse-metadata event-bytes 269)})
```

### Alerting

```clojure
(defn alert-program-errors [prog-id error-rate]
  "Alert on program error rate threshold exceeded"
  (send-alert
    {:severity :warning
     :title "BPF Program Error Rate High"
     :description (format "Program %d error rate: %.2f%%"
                         prog-id (* error-rate 100))
     :labels {:program_id prog-id
              :component "bpf-runtime"}
     :runbook "https://docs.company.com/runbooks/bpf-errors"}))

(defn alert-slow-program [prog-id avg-duration-ns]
  "Alert on slow program execution"
  (send-alert
    {:severity :info
     :title "BPF Program Performance Degraded"
     :description (format "Program %d avg duration: %.2fms"
                         prog-id (/ avg-duration-ns 1000000.0))
     :labels {:program_id prog-id
              :component "bpf-runtime"}}))

(defn send-alert [alert]
  "Send alert to alerting system (PagerDuty, Slack, etc.)"
  ;; Integration with alerting backend
  (case (:severity alert)
    :critical (pagerduty/trigger alert)
    :warning  (slack/notify "#alerts" alert)
    :info     (slack/notify "#monitoring" alert)))
```

## 23.3 Resource Management

### Memory Limits

```clojure
(defn enforce-map-size-limits []
  "Ensure BPF maps don't exceed memory limits"
  (let [total-map-memory (get-total-map-memory)
        limit (* 1024 1024 1024)]  ; 1GB limit

    (when (> total-map-memory limit)
      (println "⚠️  Map memory exceeds limit, cleaning up...")

      ;; Evict least recently used maps
      (evict-lru-maps (- total-map-memory limit)))))

(defn get-total-map-memory []
  "Calculate total memory used by all BPF maps"
  (let [maps (bpf/get-all-maps)]
    (reduce (fn [total map-info]
              (+ total (* (:max-entries map-info)
                         (+ (:key-size map-info)
                            (:value-size map-info)))))
            0
            maps)))

(defn evict-lru-maps [bytes-to-free]
  "Evict least recently used maps to free memory"
  (let [maps (sort-by :last-access-time (bpf/get-all-maps))]
    (loop [maps maps
           freed 0]
      (when (and (< freed bytes-to-free) (seq maps))
        (let [map (first maps)
              map-size (* (:max-entries map)
                         (+ (:key-size map) (:value-size map)))]
          (when (:evictable map)
            (println (format "Evicting map: %s (%d bytes)" (:name map) map-size))
            (bpf/delete-map (:id map))
            (recur (rest maps) (+ freed map-size))))))))
```

### CPU Overhead Monitoring

```clojure
(defn monitor-cpu-overhead []
  "Monitor CPU overhead from BPF programs"
  (let [baseline-cpu (get-cpu-usage)]

    ;; Let BPF programs run for measurement period
    (Thread/sleep 60000)

    (let [current-cpu (get-cpu-usage)
          overhead (- current-cpu baseline-cpu)]

      (when (> overhead 5.0)  ; 5% overhead threshold
        (println (format "⚠️  High BPF CPU overhead: %.2f%%" overhead))

        ;; Reduce sampling rates
        (reduce-sampling-rates 0.5))

      {:overhead overhead
       :baseline baseline-cpu
       :current current-cpu})))

(defn reduce-sampling-rates [factor]
  "Reduce sampling rates of all programs by factor"
  (doseq [prog (bpf/get-all-programs)]
    (when (:sampling-rate prog)
      (let [new-rate (* (:sampling-rate prog) factor)]
        (println (format "Reducing %s sampling rate: %d → %d Hz"
                        (:name prog)
                        (:sampling-rate prog)
                        new-rate))
        (bpf/update-program-config prog {:sampling-rate new-rate})))))
```

### Program Count Limits

```clojure
(def max-programs 100)

(defn check-program-limit []
  "Ensure program count doesn't exceed system limits"
  (let [current-count (count (bpf/get-all-programs))]
    (when (>= current-count max-programs)
      (throw (ex-info "Program limit exceeded"
                     {:current current-count
                      :limit max-programs})))))

(defn cleanup-unused-programs []
  "Remove programs that haven't been used recently"
  (let [programs (bpf/get-all-programs)
        cutoff-time (- (System/currentTimeMillis)
                      (* 24 60 60 1000))]  ; 24 hours

    (doseq [prog programs]
      (when (< (:last-run-time prog) cutoff-time)
        (println (format "Removing unused program: %s" (:name prog)))
        (bpf/unload-program (:id prog))))))
```

## 23.4 Security Considerations

### Capability Requirements

```clojure
(defn check-required-capabilities []
  "Verify process has required capabilities"
  (let [required-caps [:CAP_BPF :CAP_PERFMON :CAP_NET_ADMIN]]

    (doseq [cap required-caps]
      (when-not (has-capability? cap)
        (throw (ex-info (format "Missing required capability: %s" cap)
                       {:capability cap}))))))

(defn drop-unnecessary-capabilities []
  "Drop capabilities after BPF setup"
  (let [keep-caps [:CAP_BPF]]  ; Only keep essential caps

    (doseq [cap (get-all-capabilities)]
      (when-not (contains? (set keep-caps) cap)
        (drop-capability cap)))))
```

### Program Signing and Verification

```clojure
(defn verify-program-signature [program signature public-key]
  "Verify BPF program is signed by authorized key"
  (let [program-hash (hash-program program)
        valid? (crypto/verify-signature program-hash signature public-key)]

    (when-not valid?
      (throw (ex-info "Invalid program signature"
                     {:hash program-hash})))

    (println "✅ Program signature verified")
    true))

(defn load-signed-program [program-file signature-file]
  "Load BPF program only if signature is valid"
  (let [program (read-program-file program-file)
        signature (read-signature-file signature-file)
        public-key (load-trusted-public-key)]

    (verify-program-signature program signature public-key)

    ;; Load program
    (bpf/load-program program (:type program))))
```

### Sensitive Data Handling

```clojure
(defn sanitize-event [event]
  "Remove sensitive data from events before logging"
  (-> event
      (update :command-line redact-credentials)
      (update :environment-vars filter-sensitive-vars)
      (update :file-paths anonymize-user-paths)))

(defn redact-credentials [command-line]
  "Redact passwords and tokens from command line"
  (-> command-line
      (str/replace #"--password[= ]\S+" "--password=REDACTED")
      (str/replace #"--token[= ]\S+" "--token=REDACTED")
      (str/replace #"AWS_SECRET_ACCESS_KEY=\S+" "AWS_SECRET_ACCESS_KEY=REDACTED")))

(defn encrypt-sensitive-map [map-data]
  "Encrypt BPF map containing sensitive data"
  ;; Use kernel's encryption facilities
  ;; Or encrypt values before storing in map
  (let [encryption-key (derive-key)]
    (transform-map-values map-data
      (fn [value]
        (encrypt value encryption-key)))))
```

### Audit Logging

```clojure
(defn audit-log-program-load [program user]
  "Audit log when BPF program is loaded"
  (audit-log
    {:action :program_load
     :timestamp (System/currentTimeMillis)
     :user user
     :program {:name (:name program)
              :type (:type program)
              :size (program-size program)
              :hash (hash-program program)}
     :attach-points (:attach-points program)}))

(defn audit-log-map-access [map-id operation key value user]
  "Audit log sensitive map operations"
  (when (:sensitive (get-map-metadata map-id))
    (audit-log
      {:action operation
       :timestamp (System/currentTimeMillis)
       :user user
       :map-id map-id
       :key (hash key)  ; Don't log actual key
       :value-hash (hash value)})))
```

## 23.5 Configuration Management

### Configuration as Code

```clojure
(defn load-deployment-config [environment]
  "Load deployment configuration for environment"
  (let [config-file (format "config/%s.edn" environment)]
    (edn/read-string (slurp config-file))))

;; config/production.edn
{:programs
 [{:name "syscall-tracer"
   :enabled true
   :sampling-rate 1000  ; 1:1000 sampling
   :attach-points ["raw_syscalls/sys_enter" "raw_syscalls/sys_exit"]
   :filters {:pids [1234 5678]
            :syscalls [:open :read :write :close]}
   :resources {:max-memory-mb 100
              :max-cpu-percent 2}}

  {:name "network-analyzer"
   :enabled true
   :interface "eth0"
   :xdp-mode :native
   :resources {:max-memory-mb 500
              :max-cpu-percent 5}}]

 :alerts
 {:error-rate-threshold 0.01
  :latency-p99-threshold-ms 10
  :channels [:pagerduty :slack]}

 :monitoring
 {:prometheus-port 9090
  :export-interval-seconds 10}}
```

### Dynamic Configuration Updates

```clojure
(def config-map
  "Runtime configuration map"
  {:type :hash
   :key-type [64 :u8]  ; Config key
   :value-type :u64    ; Config value
   :max-entries 100})

(defn update-runtime-config [key value]
  "Update BPF program configuration at runtime"
  (println (format "Updating config: %s = %d" key value))

  ;; Update configuration map
  (bpf/map-update! config-map key value)

  ;; Config is read by BPF programs on next execution
  ;; No need to reload programs

  ;; Audit log configuration change
  (audit-log-config-change key value))

;; Example: Update sampling rate without reloading
(update-runtime-config "sampling-rate" 10000)  ; 1:10000 sampling
```

## Lab: BPF Program Lifecycle Manager

Build a complete production deployment system:

```clojure
(ns production.lifecycle-manager
  (:require [clj-ebpf.core :as bpf]))

(defn deploy-program
  "Complete deployment lifecycle"
  [program version options]

  ;; 1. Validate
  (println "1/7 Validating program...")
  (validate-program program)

  ;; 2. Check signature
  (println "2/7 Verifying signature...")
  (verify-program-signature program (:signature options) (:public-key options))

  ;; 3. Check resources
  (println "3/7 Checking resource limits...")
  (check-resource-limits program)

  ;; 4. Register version
  (println "4/7 Registering version...")
  (let [version-id (register-version program version)]

    ;; 5. Deploy (canary or blue-green)
    (println "5/7 Deploying...")
    (case (:strategy options)
      :canary (canary-deploy program (:canary-percent options))
      :blue-green (blue-green-deploy program)
      :immediate (deploy-immediate program))

    ;; 6. Health check
    (println "6/7 Health checking...")
    (let [health (check-deployment-health version-id)]
      (when-not (:healthy health)
        (println "❌ Health check failed, rolling back")
        (rollback-to-previous-version)
        (throw (ex-info "Deployment failed health check" {:health health}))))

    ;; 7. Cleanup old versions
    (println "7/7 Cleaning up...")
    (cleanup-old-versions version-id)

    (println "✅ Deployment successful")
    {:status :success
     :version-id version-id}))
```

## Summary

Production deployment of eBPF requires:
- **Robust deployment strategies** - Canary, blue-green, with automatic rollback
- **Comprehensive monitoring** - Metrics, logs, alerts for all programs
- **Resource management** - Memory limits, CPU overhead control
- **Security hardening** - Capabilities, signing, sensitive data protection
- **Configuration management** - Version control, dynamic updates

**Next Chapter**: [Chapter 24: Troubleshooting Guide](../chapter-02/README.md)
