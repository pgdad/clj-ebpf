# Chapter 20: Production Deployment

**Duration**: 3-4 hours | **Difficulty**: Advanced

This chapter covers best practices for deploying BPF applications in production environments, including monitoring, observability, reliability patterns, and operational considerations.

## Learning Objectives

By the end of this chapter, you will:
- Deploy BPF applications with proper operational controls
- Implement comprehensive monitoring and alerting
- Build resilient BPF systems with graceful degradation
- Manage BPF application lifecycle in production
- Troubleshoot production issues effectively

## Prerequisites

- Completed Chapters 10-19
- Understanding of production operations
- Familiarity with monitoring systems

---

## 20.1 Deployment Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Control Plane                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Config    │  │   Policy    │  │    Orchestration    │ │
│  │   Manager   │  │   Engine    │  │      (K8s/etc)      │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Data Plane (per Node)                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   BPF       │  │   Agent     │  │      Metrics        │ │
│  │  Programs   │◄─┤  (clj-ebpf) │──┤     Exporter        │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│         │                                     │             │
│         ▼                                     ▼             │
│  ┌─────────────┐                    ┌─────────────────────┐ │
│  │   Kernel    │                    │    Prometheus/      │ │
│  │   Events    │                    │    Monitoring       │ │
│  └─────────────┘                    └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 20.2 Configuration Management

### Externalized Configuration

```clojure
(defn load-config [config-path]
  "Load configuration from file or environment"
  (let [file-config (when (io/file-exists? config-path)
                      (read-edn config-path))
        env-config {:log-level (System/getenv "BPF_LOG_LEVEL")
                    :metrics-port (parse-int (System/getenv "METRICS_PORT"))
                    :enable-debug (= "true" (System/getenv "BPF_DEBUG"))}]
    (merge default-config file-config env-config)))

(def default-config
  {:log-level :info
   :metrics-port 9090
   :health-check-port 8080
   :bpf-map-size 65536
   :ring-buffer-size (* 256 1024)
   :enable-debug false
   :feature-flags {:new-parser false
                   :enhanced-metrics false}})
```

### Dynamic Configuration Updates

```clojure
(def config-version (atom 0))

(defn update-runtime-config! [updates]
  "Update configuration without restart"
  (swap! config-version inc)
  (let [version @config-version]
    (doseq [[key value] updates]
      (case key
        :rate-limit (update-bpf-map! rate-limit-map 0 value)
        :blocked-ips (sync-blocked-ips! value)
        :feature-flags (update-feature-flags! value)
        (log/warn "Unknown config key:" key)))
    (log/info "Config updated to version" version)))
```

---

## 20.3 Monitoring and Observability

### Metrics Export

```clojure
(defn create-metrics-exporter []
  {:counters
   {:packets-processed (prometheus/counter "bpf_packets_processed_total"
                                           "Total packets processed")
    :packets-dropped (prometheus/counter "bpf_packets_dropped_total"
                                         "Total packets dropped")
    :errors (prometheus/counter "bpf_errors_total"
                               "Total errors")}

   :gauges
   {:map-entries (prometheus/gauge "bpf_map_entries"
                                   "Number of map entries")
    :ring-buffer-usage (prometheus/gauge "bpf_ringbuf_usage_percent"
                                         "Ring buffer usage percentage")}

   :histograms
   {:processing-latency (prometheus/histogram "bpf_processing_latency_ns"
                                              "Processing latency"
                                              {:buckets [100 500 1000 5000 10000]})}})

(defn collect-bpf-metrics [exporter bpf-context]
  "Collect metrics from BPF maps"
  (let [{:keys [counters gauges histograms]} exporter]

    ;; Update counters from per-CPU maps
    (prometheus/inc! (:packets-processed counters)
                     (sum-percpu-map (:stats-map bpf-context) :packets))

    ;; Update gauges
    (prometheus/set! (:map-entries gauges)
                     (count-map-entries (:connection-map bpf-context)))

    ;; Ring buffer metrics
    (prometheus/set! (:ring-buffer-usage gauges)
                     (get-ringbuf-usage-percent (:event-buffer bpf-context)))))
```

### Health Checks

```clojure
(defn create-health-checker [bpf-context]
  {:checks
   [{:name "bpf-programs-loaded"
     :check-fn #(every? loaded? (:programs bpf-context))
     :critical true}

    {:name "maps-accessible"
     :check-fn #(every? accessible? (:maps bpf-context))
     :critical true}

    {:name "ring-buffer-healthy"
     :check-fn #(< (get-ringbuf-usage-percent (:event-buffer bpf-context)) 90)
     :critical false}

    {:name "event-processing-rate"
     :check-fn #(> (get-events-per-second bpf-context) 0)
     :critical false}]

   :endpoints
   {:liveness "/health/live"
    :readiness "/health/ready"}})

(defn run-health-checks [checker]
  (let [results (for [{:keys [name check-fn critical]} (:checks checker)]
                  {:name name
                   :healthy (try (check-fn) (catch Exception _ false))
                   :critical critical})]
    {:healthy (every? :healthy results)
     :details results
     :timestamp (System/currentTimeMillis)}))
```

---

## 20.4 Reliability Patterns

### Graceful Degradation

```clojure
(defn create-resilient-processor [primary-processor fallback-processor]
  (let [failure-count (atom 0)
        circuit-open (atom false)
        last-failure-time (atom 0)]

    (fn [event]
      (if @circuit-open
        ;; Circuit is open, use fallback
        (do
          (when (> (- (System/currentTimeMillis) @last-failure-time) 30000)
            ;; Try to close circuit after 30 seconds
            (reset! circuit-open false)
            (reset! failure-count 0))
          (fallback-processor event))

        ;; Try primary processor
        (try
          (let [result (primary-processor event)]
            (reset! failure-count 0)
            result)
          (catch Exception e
            (swap! failure-count inc)
            (reset! last-failure-time (System/currentTimeMillis))
            (when (> @failure-count 5)
              (reset! circuit-open true)
              (log/error "Circuit breaker opened after 5 failures"))
            (fallback-processor event)))))))
```

### Resource Limits

```clojure
(defn enforce-resource-limits [context limits]
  "Enforce resource limits to prevent runaway consumption"
  (let [{:keys [max-map-entries max-events-per-sec max-memory-mb]} limits]

    ;; Check map sizes
    (doseq [[name map-ref] (:maps context)]
      (when (> (count-map-entries map-ref) max-map-entries)
        (log/warn "Map" name "exceeds limit, triggering cleanup")
        (cleanup-old-entries map-ref)))

    ;; Check event rate
    (when (> (get-events-per-second context) max-events-per-sec)
      (log/warn "Event rate exceeds limit, enabling sampling")
      (enable-sampling! context (/ max-events-per-sec
                                   (get-events-per-second context))))

    ;; Check memory (ring buffer)
    (when (> (get-memory-usage-mb context) max-memory-mb)
      (log/warn "Memory usage high, draining ring buffer")
      (drain-ring-buffer! (:event-buffer context)))))
```

---

## 20.5 Operational Runbooks

### Startup Sequence

```clojure
(defn production-startup []
  (log/info "Starting BPF application...")

  ;; 1. Load configuration
  (log/info "Loading configuration...")
  (let [config (load-config "/etc/bpf-app/config.edn")]

    ;; 2. Initialize metrics
    (log/info "Initializing metrics...")
    (init-metrics! (:metrics-port config))

    ;; 3. Load BPF programs
    (log/info "Loading BPF programs...")
    (let [programs (load-all-programs config)]
      (when-not (every? :success programs)
        (throw (ex-info "Failed to load programs"
                        {:failed (filter #(not (:success %)) programs)}))))

    ;; 4. Create maps
    (log/info "Creating BPF maps...")
    (let [maps (create-all-maps config)]

      ;; 5. Attach programs
      (log/info "Attaching programs...")
      (attach-all-programs programs (:attach-points config))

      ;; 6. Start health check server
      (log/info "Starting health check server...")
      (start-health-server (:health-check-port config))

      ;; 7. Mark ready
      (log/info "Application ready")
      (signal-ready!)

      {:config config :programs programs :maps maps})))
```

### Graceful Shutdown

```clojure
(defn production-shutdown [context]
  (log/info "Initiating graceful shutdown...")

  ;; 1. Stop accepting new work
  (log/info "Stopping new work...")
  (signal-not-ready!)

  ;; 2. Drain in-flight events
  (log/info "Draining events (30s timeout)...")
  (drain-events! context 30000)

  ;; 3. Detach programs
  (log/info "Detaching programs...")
  (detach-all-programs (:programs context))

  ;; 4. Export final metrics
  (log/info "Exporting final metrics...")
  (export-final-metrics!)

  ;; 5. Close maps
  (log/info "Closing maps...")
  (close-all-maps (:maps context))

  ;; 6. Unload programs
  (log/info "Unloading programs...")
  (unload-all-programs (:programs context))

  (log/info "Shutdown complete"))

;; Signal handlers
(defn register-shutdown-hook [context]
  (.addShutdownHook
    (Runtime/getRuntime)
    (Thread. #(production-shutdown context))))
```

---

## 20.6 Troubleshooting Guide

### Common Issues

| Issue | Symptoms | Resolution |
|-------|----------|------------|
| Program won't load | Verifier error | Check bounds, loops, helpers |
| High CPU usage | `perf top` shows BPF | Optimize hot path, reduce events |
| Events missing | Counter mismatch | Check ring buffer size, drop stats |
| Map full | Lookup failures | Increase size, add eviction |
| Latency spike | P99 increase | Profile, check lock contention |

### Diagnostic Commands

```clojure
(defn run-diagnostics [context]
  (println "\n=== BPF Application Diagnostics ===\n")

  ;; Program status
  (println "Programs:")
  (doseq [prog (:programs context)]
    (println (format "  %s: %s (ID: %d)"
                     (:name prog)
                     (if (loaded? prog) "LOADED" "NOT LOADED")
                     (:id prog))))

  ;; Map status
  (println "\nMaps:")
  (doseq [[name map-ref] (:maps context)]
    (println (format "  %s: %d entries (max: %d)"
                     name
                     (count-map-entries map-ref)
                     (:max-entries map-ref))))

  ;; Performance
  (println "\nPerformance:")
  (println (format "  Events/sec: %.2f" (get-events-per-second context)))
  (println (format "  Drops/sec: %.2f" (get-drops-per-second context)))
  (println (format "  Avg latency: %.2f μs" (get-avg-latency-us context)))

  ;; Health
  (println "\nHealth:")
  (let [health (run-health-checks (:health-checker context))]
    (doseq [{:keys [name healthy critical]} (:details health)]
      (println (format "  %s: %s%s"
                       name
                       (if healthy "OK" "FAILED")
                       (if critical " [CRITICAL]" ""))))))
```

---

## Labs

### Lab 20.1: Production-Ready Deployment

Build a complete production deployment with monitoring.

[Go to Lab 20.1](labs/lab-20-1-production-deployment.md)

### Lab 20.2: Incident Response

Practice incident response procedures for BPF issues.

[Go to Lab 20.2](labs/lab-20-2-incident-response.md)

### Lab 20.3: Capacity Planning

Learn to plan and size BPF deployments.

[Go to Lab 20.3](labs/lab-20-3-capacity-planning.md)

---

## Key Takeaways

1. **Configuration**: Externalize, validate, support hot reload
2. **Monitoring**: Comprehensive metrics, health checks, alerting
3. **Reliability**: Circuit breakers, graceful degradation, resource limits
4. **Operations**: Clear startup/shutdown, runbooks, diagnostics
5. **Troubleshooting**: Know common issues, have diagnostic tools ready

## References

- [BPF CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [Production BPF](https://www.brendangregg.com/blog/2019-12-02/bpf-production-environment.html)
- [Cilium Operations](https://docs.cilium.io/en/stable/operations/)
