;; Lab 20.1 Solution: Production-Ready Deployment
;; Complete production-ready BPF deployment with configuration, monitoring, health checks

(ns lab-20-1-production-deployment
  (:require [clojure.string :as str]
            [clojure.edn :as edn]
            [clj-ebpf.core :as ebpf])
  (:import [java.util.concurrent ConcurrentHashMap Executors ScheduledExecutorService TimeUnit]
           [java.util.concurrent.atomic AtomicLong AtomicBoolean AtomicReference]
           [java.net ServerSocket Socket InetSocketAddress]
           [java.io BufferedReader InputStreamReader PrintWriter]
           [java.time Instant ZonedDateTime ZoneId]
           [java.time.format DateTimeFormatter]))

;; =============================================================================
;; Part 1: Application Structure and Records
;; =============================================================================

(defrecord BPFProgram [id name type status loaded-at attach-point stats])

(defrecord BPFMap [id name type max-entries key-size value-size current-entries])

(defrecord HealthStatus [healthy? components last-check message])

(defrecord BPFApplication [config programs maps metrics health-status
                           servers scheduler shutdown-flag])

(def app-state (atom nil))

(defn create-application
  "Create a new BPF application instance."
  [config]
  (map->BPFApplication
   {:config config
    :programs (atom {})
    :maps (atom {})
    :metrics (ConcurrentHashMap.)
    :health-status (atom (->HealthStatus true {} (System/currentTimeMillis) "Initializing"))
    :servers (atom {})
    :scheduler (Executors/newScheduledThreadPool 2)
    :shutdown-flag (AtomicBoolean. false)}))

;; =============================================================================
;; Part 2: Configuration Management
;; =============================================================================

(def default-config
  {:app-name "bpf-monitor"
   :version "1.0.0"
   :environment :development
   :metrics-port 9090
   :health-port 8080
   :log-level :info
   :programs {:default {:type :kprobe
                        :attach-points ["sys_enter_read" "sys_enter_write"]}}
   :maps {:events {:type :ring-buffer
                   :size 65536}
          :stats {:type :hash
                  :max-entries 10000
                  :key-size 8
                  :value-size 64}}
   :health {:check-interval-ms 5000
            :timeout-ms 3000
            :error-threshold 0.01}
   :metrics {:export-interval-ms 10000
             :retention-seconds 3600}})

(defn deep-merge
  "Deep merge two maps."
  [a b]
  (if (and (map? a) (map? b))
    (merge-with deep-merge a b)
    b))

(defn load-config
  "Load configuration from file, merging with defaults."
  [path]
  (let [file-config (when (and path (.exists (java.io.File. path)))
                      (try
                        (edn/read-string (slurp path))
                        (catch Exception e
                          (println "Warning: Could not load config from" path ":" (.getMessage e))
                          {})))]
    (deep-merge default-config (or file-config {}))))

(defn validate-config
  "Validate configuration and return errors."
  [config]
  (let [errors (atom [])]
    (when (not (string? (:app-name config)))
      (swap! errors conj "app-name must be a string"))
    (when (not (#{:development :staging :production} (:environment config)))
      (swap! errors conj "environment must be :development, :staging, or :production"))
    (when (not (<= 1024 (:metrics-port config) 65535))
      (swap! errors conj "metrics-port must be between 1024 and 65535"))
    (when (not (<= 1024 (:health-port config) 65535))
      (swap! errors conj "health-port must be between 1024 and 65535"))
    @errors))

(defn print-config
  "Print configuration summary."
  [config]
  (println "\n=== Configuration ===")
  (println (format "App Name:    %s" (:app-name config)))
  (println (format "Version:     %s" (:version config)))
  (println (format "Environment: %s" (name (:environment config))))
  (println (format "Log Level:   %s" (name (:log-level config))))
  (println (format "Metrics:     http://localhost:%d/metrics" (:metrics-port config)))
  (println (format "Health:      http://localhost:%d/health" (:health-port config))))

;; =============================================================================
;; Part 3: Logging System
;; =============================================================================

(def log-levels {:trace 0 :debug 1 :info 2 :warn 3 :error 4})

(defn log
  "Log a message at the specified level."
  [app level message & args]
  (let [config-level (get-in app [:config :log-level] :info)
        formatter (DateTimeFormatter/ofPattern "yyyy-MM-dd HH:mm:ss.SSS")]
    (when (>= (get log-levels level 2) (get log-levels config-level 2))
      (let [timestamp (.format (ZonedDateTime/now (ZoneId/systemDefault)) formatter)]
        (println (format "[%s] [%s] %s"
                         timestamp
                         (str/upper-case (name level))
                         (apply format message args)))))))

(defn log-info [app msg & args] (apply log app :info msg args))
(defn log-warn [app msg & args] (apply log app :warn msg args))
(defn log-error [app msg & args] (apply log app :error msg args))
(defn log-debug [app msg & args] (apply log app :debug msg args))

;; =============================================================================
;; Part 4: Mock BPF Infrastructure (for testing without root)
;; =============================================================================

(defn mock-load-program
  "Mock loading a BPF program."
  [app program-id config]
  (let [program (->BPFProgram
                 program-id
                 (name program-id)
                 (:type config :kprobe)
                 :loaded
                 (System/currentTimeMillis)
                 (:attach-points config [])
                 (atom {:invocations 0 :errors 0 :total-ns 0}))]
    (swap! (:programs app) assoc program-id program)
    (log-info app "Loaded program: %s (type: %s)" (name program-id) (name (:type config)))
    program))

(defn mock-create-map
  "Mock creating a BPF map."
  [app map-id config]
  (let [bpf-map (->BPFMap
                 map-id
                 (name map-id)
                 (:type config :hash)
                 (:max-entries config 10000)
                 (:key-size config 8)
                 (:value-size config 64)
                 (AtomicLong. 0))]
    (swap! (:maps app) assoc map-id bpf-map)
    (log-info app "Created map: %s (type: %s, max-entries: %d)"
              (name map-id) (name (:type config)) (:max-entries config))
    bpf-map))

(defn load-programs!
  "Load all configured BPF programs."
  [app]
  (log-info app "Loading BPF programs...")
  (doseq [[prog-id prog-config] (get-in app [:config :programs])]
    (mock-load-program app prog-id prog-config))
  (log-info app "Loaded %d programs" (count @(:programs app))))

(defn create-maps!
  "Create all configured BPF maps."
  [app]
  (log-info app "Creating BPF maps...")
  (doseq [[map-id map-config] (get-in app [:config :maps])]
    (mock-create-map app map-id map-config))
  (log-info app "Created %d maps" (count @(:maps app))))

(defn unload-programs!
  "Unload all BPF programs."
  [app]
  (log-info app "Unloading BPF programs...")
  (doseq [[prog-id _] @(:programs app)]
    (log-debug app "Unloading program: %s" (name prog-id)))
  (reset! (:programs app) {})
  (log-info app "All programs unloaded"))

;; =============================================================================
;; Part 5: Metrics System
;; =============================================================================

(defn increment-metric!
  "Increment a metric counter."
  [app metric-name]
  (let [counter (.computeIfAbsent (:metrics app) (name metric-name)
                                  (fn [_] (AtomicLong.)))]
    (.incrementAndGet counter)))

(defn add-metric!
  "Add value to a metric."
  [app metric-name value]
  (let [counter (.computeIfAbsent (:metrics app) (name metric-name)
                                  (fn [_] (AtomicLong.)))]
    (.addAndGet counter value)))

(defn set-metric!
  "Set a metric to specific value."
  [app metric-name value]
  (let [counter (.computeIfAbsent (:metrics app) (name metric-name)
                                  (fn [_] (AtomicLong.)))]
    (.set counter value)))

(defn get-metric
  "Get current value of a metric."
  [app metric-name]
  (if-let [counter (.get (:metrics app) (name metric-name))]
    (.get counter)
    0))

(defn get-all-metrics
  "Get all metrics as a map."
  [app]
  (into {}
        (map (fn [[k v]] [(keyword k) (.get v)])
             (:metrics app))))

(defn format-prometheus-metrics
  "Format metrics in Prometheus format."
  [app]
  (let [config (:config app)
        metrics (get-all-metrics app)
        lines (atom [])]
    ;; Add app info
    (swap! lines conj (format "# HELP %s_info Application information"
                              (:app-name config)))
    (swap! lines conj (format "# TYPE %s_info gauge"
                              (:app-name config)))
    (swap! lines conj (format "%s_info{version=\"%s\",environment=\"%s\"} 1"
                              (:app-name config)
                              (:version config)
                              (name (:environment config))))

    ;; Add program stats
    (doseq [[prog-id prog] @(:programs app)]
      (let [stats @(:stats prog)]
        (swap! lines conj (format "bpf_program_invocations{program=\"%s\"} %d"
                                  (name prog-id) (:invocations stats)))
        (swap! lines conj (format "bpf_program_errors{program=\"%s\"} %d"
                                  (name prog-id) (:errors stats)))))

    ;; Add map stats
    (doseq [[map-id bpf-map] @(:maps app)]
      (swap! lines conj (format "bpf_map_entries{map=\"%s\"} %d"
                                (name map-id) (.get (:current-entries bpf-map))))
      (swap! lines conj (format "bpf_map_max_entries{map=\"%s\"} %d"
                                (name map-id) (:max-entries bpf-map))))

    ;; Add custom metrics
    (doseq [[metric-name value] metrics]
      (swap! lines conj (format "%s %d" (name metric-name) value)))

    (str/join "\n" @lines)))

;; =============================================================================
;; Part 6: Health Check System
;; =============================================================================

(defn programs-loaded?
  "Check if all programs are loaded."
  [app]
  (let [expected (count (get-in app [:config :programs]))
        actual (count @(:programs app))]
    (and (pos? actual) (= expected actual))))

(defn maps-accessible?
  "Check if all maps are accessible."
  [app]
  (let [expected (count (get-in app [:config :maps]))
        actual (count @(:maps app))]
    (and (pos? actual) (= expected actual))))

(defn get-error-rate
  "Calculate current error rate from metrics."
  [app]
  (let [total (get-metric app :total_events)
        errors (get-metric app :error_events)]
    (if (pos? total)
      (double (/ errors total))
      0.0)))

(defn check-component-health
  "Check health of a specific component."
  [app component]
  (case component
    :programs {:healthy (programs-loaded? app)
               :message (if (programs-loaded? app)
                          "All programs loaded"
                          "Programs not loaded")}
    :maps {:healthy (maps-accessible? app)
           :message (if (maps-accessible? app)
                      "All maps accessible"
                      "Maps not accessible")}
    :error-rate (let [rate (get-error-rate app)
                      threshold (get-in app [:config :health :error-threshold] 0.01)]
                  {:healthy (< rate threshold)
                   :message (format "Error rate: %.4f (threshold: %.4f)" rate threshold)})
    {:healthy true :message "Unknown component"}))

(defn healthy?
  "Check if application is healthy."
  [app]
  (and (programs-loaded? app)
       (maps-accessible? app)
       (< (get-error-rate app) (get-in app [:config :health :error-threshold] 0.01))))

(defn get-health-status
  "Get detailed health status."
  [app]
  (let [components {:programs (check-component-health app :programs)
                    :maps (check-component-health app :maps)
                    :error-rate (check-component-health app :error-rate)}
        all-healthy (every? :healthy (vals components))]
    (->HealthStatus
     all-healthy
     components
     (System/currentTimeMillis)
     (if all-healthy "All systems operational" "Degraded"))))

(defn update-health-status!
  "Update the cached health status."
  [app]
  (reset! (:health-status app) (get-health-status app)))

;; =============================================================================
;; Part 7: HTTP Server (Simple Implementation)
;; =============================================================================

(defn parse-http-request
  "Parse simple HTTP request."
  [reader]
  (let [request-line (.readLine reader)]
    (when request-line
      (let [[method path _] (str/split request-line #" ")]
        {:method method
         :path path}))))

(defn send-http-response
  "Send HTTP response."
  [writer status content-type body]
  (let [status-text (case status
                      200 "OK"
                      404 "Not Found"
                      500 "Internal Server Error"
                      503 "Service Unavailable"
                      "Unknown")]
    (.print writer (str "HTTP/1.1 " status " " status-text "\r\n"))
    (.print writer (str "Content-Type: " content-type "\r\n"))
    (.print writer (str "Content-Length: " (count (.getBytes body "UTF-8")) "\r\n"))
    (.print writer "Connection: close\r\n")
    (.print writer "\r\n")
    (.print writer body)
    (.flush writer)))

(defn health-handler
  "Handle health check requests."
  [app req]
  (let [status (get-health-status app)]
    {:status (if (:healthy? status) 200 503)
     :content-type "application/json"
     :body (pr-str {:healthy (:healthy? status)
                    :timestamp (:last-check status)
                    :message (:message status)
                    :components (into {}
                                      (map (fn [[k v]] [k (:message v)])
                                           (:components status)))})}))

(defn metrics-handler
  "Handle metrics requests."
  [app req]
  {:status 200
   :content-type "text/plain"
   :body (format-prometheus-metrics app)})

(defn start-http-server
  "Start a simple HTTP server."
  [app port handler-fn server-name]
  (let [server-socket (ServerSocket. port)
        running (AtomicBoolean. true)]
    (log-info app "Starting %s server on port %d" server-name port)
    (future
      (try
        (while (and (.get running) (not (.get (:shutdown-flag app))))
          (try
            (.setSoTimeout server-socket 1000)
            (let [client-socket (.accept server-socket)]
              (future
                (try
                  (with-open [reader (BufferedReader. (InputStreamReader. (.getInputStream client-socket)))
                              writer (PrintWriter. (.getOutputStream client-socket))]
                    (let [req (parse-http-request reader)
                          resp (handler-fn app req)]
                      (send-http-response writer
                                          (:status resp)
                                          (:content-type resp)
                                          (:body resp))))
                  (catch Exception e
                    (log-debug app "Client error: %s" (.getMessage e)))
                  (finally
                    (.close client-socket)))))
            (catch java.net.SocketTimeoutException _)))
        (catch Exception e
          (when (.get running)
            (log-error app "Server error: %s" (.getMessage e))))
        (finally
          (.close server-socket))))
    {:socket server-socket
     :running running}))

(defn stop-http-server
  "Stop an HTTP server."
  [server]
  (when server
    (.set (:running server) false)
    (try
      (.close (:socket server))
      (catch Exception _))))

(defn start-health-server!
  "Start the health check server."
  [app]
  (let [port (get-in app [:config :health-port] 8080)
        server (start-http-server app port health-handler "health")]
    (swap! (:servers app) assoc :health server)))

(defn start-metrics-server!
  "Start the metrics server."
  [app]
  (let [port (get-in app [:config :metrics-port] 9090)
        server (start-http-server app port metrics-handler "metrics")]
    (swap! (:servers app) assoc :metrics server)))

(defn stop-health-server!
  "Stop the health check server."
  [app]
  (when-let [server (:health @(:servers app))]
    (stop-http-server server)
    (log-info app "Health server stopped")))

(defn stop-metrics-server!
  "Stop the metrics server."
  [app]
  (when-let [server (:metrics @(:servers app))]
    (stop-http-server server)
    (log-info app "Metrics server stopped")))

;; =============================================================================
;; Part 8: Background Tasks
;; =============================================================================

(defn schedule-health-checks!
  "Schedule periodic health checks."
  [app]
  (let [interval-ms (get-in app [:config :health :check-interval-ms] 5000)]
    (.scheduleAtFixedRate
     (:scheduler app)
     (fn []
       (try
         (update-health-status! app)
         (catch Exception e
           (log-error app "Health check error: %s" (.getMessage e)))))
     0
     interval-ms
     TimeUnit/MILLISECONDS)
    (log-info app "Health checks scheduled every %d ms" interval-ms)))

(defn schedule-metrics-export!
  "Schedule periodic metrics export."
  [app]
  (let [interval-ms (get-in app [:config :metrics :export-interval-ms] 10000)]
    (.scheduleAtFixedRate
     (:scheduler app)
     (fn []
       (try
         ;; Update derived metrics
         (set-metric! app :uptime_seconds
                      (quot (- (System/currentTimeMillis)
                               (get-metric app :start_time))
                            1000))
         (catch Exception e
           (log-error app "Metrics export error: %s" (.getMessage e)))))
     interval-ms
     interval-ms
     TimeUnit/MILLISECONDS)
    (log-info app "Metrics export scheduled every %d ms" interval-ms)))

;; =============================================================================
;; Part 9: Lifecycle Management
;; =============================================================================

(declare stop!)

(defn add-shutdown-hook!
  "Add JVM shutdown hook."
  [app]
  (.addShutdownHook
   (Runtime/getRuntime)
   (Thread. #(do
               (println "\nShutdown signal received")
               (stop!)))))

(defn start!
  "Start the BPF application."
  [config-path]
  (let [config (load-config config-path)
        errors (validate-config config)]
    (if (seq errors)
      (do
        (println "Configuration errors:")
        (doseq [e errors] (println "  -" e))
        nil)
      (let [app (create-application config)]
        (print-config config)
        (log-info app "Starting application %s v%s..."
                  (:app-name config) (:version config))

        ;; Initialize
        (set-metric! app :start_time (System/currentTimeMillis))
        (load-programs! app)
        (create-maps! app)

        ;; Start servers
        (start-health-server! app)
        (start-metrics-server! app)

        ;; Schedule background tasks
        (schedule-health-checks! app)
        (schedule-metrics-export! app)

        ;; Register shutdown hook
        (add-shutdown-hook! app)

        ;; Store in global state
        (reset! app-state app)

        (log-info app "Application started successfully")
        app))))

(defn stop!
  "Stop the BPF application."
  []
  (when-let [app @app-state]
    (log-info app "Stopping application...")
    (.set (:shutdown-flag app) true)

    ;; Stop servers
    (stop-health-server! app)
    (stop-metrics-server! app)

    ;; Shutdown scheduler
    (.shutdown (:scheduler app))
    (.awaitTermination (:scheduler app) 5 TimeUnit/SECONDS)

    ;; Unload programs
    (unload-programs! app)

    ;; Clear state
    (reset! app-state nil)
    (println "Application stopped")))

;; =============================================================================
;; Part 10: Testing and Demo
;; =============================================================================

(defn simulate-events
  "Simulate BPF events for testing."
  [app count]
  (log-info app "Simulating %d events..." count)
  (dotimes [i count]
    (increment-metric! app :total_events)
    ;; Simulate occasional errors
    (when (< (rand) 0.001)
      (increment-metric! app :error_events))
    ;; Update program stats
    (doseq [[_ prog] @(:programs app)]
      (swap! (:stats prog) update :invocations inc)
      (swap! (:stats prog) update :total-ns + (rand-int 10000)))
    ;; Update map entries
    (doseq [[_ bpf-map] @(:maps app)]
      (when (< (.get (:current-entries bpf-map)) (:max-entries bpf-map))
        (.incrementAndGet (:current-entries bpf-map)))))
  (log-info app "Simulation complete"))

(defn run-tests
  "Run all tests."
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "Running Production Deployment Tests")
  (println (str/join "" (repeat 60 "=")))

  ;; Test configuration
  (println "\n=== Testing Configuration ===")
  (let [config (load-config nil)]
    (println "Default config loaded:" (pr-str (select-keys config [:app-name :version :environment])))
    (println "Validation:" (if (empty? (validate-config config)) "PASSED" "FAILED")))

  ;; Test application lifecycle
  (println "\n=== Testing Application Lifecycle ===")
  (let [app (create-application default-config)]
    (println "Application created")
    (load-programs! app)
    (create-maps! app)
    (println (format "Programs: %d, Maps: %d"
                     (count @(:programs app))
                     (count @(:maps app))))
    (println "Health check:" (if (healthy? app) "HEALTHY" "UNHEALTHY"))
    (unload-programs! app)
    (println "Programs unloaded"))

  ;; Test metrics
  (println "\n=== Testing Metrics ===")
  (let [app (create-application default-config)]
    (increment-metric! app :test_counter)
    (increment-metric! app :test_counter)
    (add-metric! app :test_sum 100)
    (println (format "Counter: %d, Sum: %d"
                     (get-metric app :test_counter)
                     (get-metric app :test_sum))))

  (println "\n" (str/join "" (repeat 60 "=")))
  (println "All tests completed!")
  (println (str/join "" (repeat 60 "="))))

(defn demo
  "Run interactive demo."
  []
  (println "\n=== Production Deployment Demo ===\n")

  ;; Start application
  (println "Starting application with default config...")
  (let [app (start! nil)]
    (when app
      (Thread/sleep 1000)

      ;; Simulate events
      (simulate-events app 1000)

      ;; Show health
      (println "\n=== Health Status ===")
      (let [status @(:health-status app)]
        (println (format "Healthy: %s" (:healthy? status)))
        (println (format "Message: %s" (:message status))))

      ;; Show metrics
      (println "\n=== Sample Metrics ===")
      (let [metrics (format-prometheus-metrics app)]
        (println (subs metrics 0 (min 500 (count metrics)))))
      (println "...")

      (println "\nServers running:")
      (println (format "  Health: http://localhost:%d/health"
                       (get-in app [:config :health-port])))
      (println (format "  Metrics: http://localhost:%d/metrics"
                       (get-in app [:config :metrics-port])))

      ;; Wait for user
      (println "\nPress Ctrl+C to stop...")
      (Thread/sleep 5000)

      ;; Stop
      (stop!))))

;; =============================================================================
;; Part 11: Main Entry Point
;; =============================================================================

(defn -main
  "Main entry point."
  [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (demo)
      "start" (do
                (start! (second args))
                ;; Keep running
                (while @app-state
                  (Thread/sleep 1000)))
      ;; Default
      (do
        (println "Production Deployment System")
        (println "Usage: clj -M -m lab-20-1.production-deployment [command]")
        (println "Commands:")
        (println "  test           - Run tests")
        (println "  demo           - Run interactive demo")
        (println "  start [config] - Start application with optional config file")
        (println "\nRunning tests by default...\n")
        (run-tests)))))

;; =============================================================================
;; Exercises
;; =============================================================================

(comment
  ;; Exercise 1: Add configuration hot-reloading
  ;; Implement watching config file for changes and reloading

  ;; Exercise 2: Add graceful degradation
  ;; Implement fallback behavior when components fail

  ;; Exercise 3: Add distributed tracing
  ;; Implement request tracing across components

  ;; Exercise 4: Add alerting integration
  ;; Implement webhook notifications for health status changes

  ;; Exercise 5: Add rolling restart capability
  ;; Implement zero-downtime restart mechanism
  )
