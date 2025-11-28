;; Lab 19.2 Solution: XDP Load Balancer
;; Implement a layer-4 load balancer using XDP
;;
;; Learning Goals:
;; - Implement multiple load balancing algorithms
;; - Build connection tracking for session persistence
;; - Health checking for backend servers
;; - XDP redirect for traffic distribution

(ns lab-19-2-load-balancer
  (:require [clojure.string :as str])
  (:import [java.util.concurrent.atomic AtomicLong AtomicInteger]
           [java.time Instant Duration]
           [java.util UUID]))

;; ============================================================================
;; XDP Actions
;; ============================================================================

(def XDP_DROP 1)
(def XDP_PASS 2)
(def XDP_TX 3)
(def XDP_REDIRECT 4)

;; ============================================================================
;; IP Utilities
;; ============================================================================

(defn ip->int [ip-str]
  (let [parts (str/split ip-str #"\.")
        bytes (map #(Integer/parseInt %) parts)]
    (reduce (fn [acc b] (+ (* acc 256) b)) 0 bytes)))

(defn int->ip [n]
  (str/join "." [(bit-and (bit-shift-right n 24) 0xFF)
                 (bit-and (bit-shift-right n 16) 0xFF)
                 (bit-and (bit-shift-right n 8) 0xFF)
                 (bit-and n 0xFF)]))

;; ============================================================================
;; Backend Server
;; ============================================================================

(defrecord Backend [id ip port weight health connections last-check response-time])

(defn create-backend
  "Create a backend server"
  [id ip port & {:keys [weight] :or {weight 1}}]
  (->Backend
    id
    (if (string? ip) (ip->int ip) ip)
    port
    weight
    (atom true)  ; healthy
    (AtomicLong. 0)  ; connections
    (atom (Instant/now))
    (atom 0)))  ; response time in ms

(defn backend-healthy? [backend]
  @(:health backend))

(defn set-backend-health! [backend healthy]
  (reset! (:health backend) healthy))

(defn increment-connections! [backend]
  (.incrementAndGet ^AtomicLong (:connections backend)))

(defn decrement-connections! [backend]
  (.decrementAndGet ^AtomicLong (:connections backend)))

(defn get-connections [backend]
  (.get ^AtomicLong (:connections backend)))

(defn update-response-time! [backend time-ms]
  (reset! (:response-time backend) time-ms))

;; ============================================================================
;; Load Balancer Configuration
;; ============================================================================

(defrecord LoadBalancerConfig [vip vport backends algorithm health-check-interval
                               connection-timeout sticky-sessions])

(def lb-config (atom nil))

(defn create-lb-config
  "Create load balancer configuration"
  [vip vport & {:keys [algorithm health-check-interval connection-timeout sticky-sessions]
                 :or {algorithm :round-robin
                      health-check-interval 5000
                      connection-timeout 300000
                      sticky-sessions false}}]
  (->LoadBalancerConfig
    (if (string? vip) (ip->int vip) vip)
    vport
    (atom [])
    (atom algorithm)
    health-check-interval
    connection-timeout
    sticky-sessions))

(defn add-backend!
  "Add a backend to the load balancer"
  [config backend]
  (swap! (:backends config) conj backend)
  (println (format "Added backend: %s (%s:%d, weight=%d)"
                   (:id backend)
                   (int->ip (:ip backend))
                   (:port backend)
                   (:weight backend))))

(defn remove-backend!
  "Remove a backend by ID"
  [config backend-id]
  (swap! (:backends config)
         (fn [backends]
           (vec (remove #(= backend-id (:id %)) backends)))))

(defn get-healthy-backends
  "Get list of healthy backends"
  [config]
  (filter backend-healthy? @(:backends config)))

(defn set-algorithm!
  "Set the load balancing algorithm"
  [config algorithm]
  (reset! (:algorithm config) algorithm)
  (println (format "Algorithm set to: %s" (name algorithm))))

;; ============================================================================
;; Connection Table
;; ============================================================================

(def connection-table
  "Connection tracking for session persistence"
  (atom {}))

(defn flow-key
  "Generate flow key from packet"
  [packet]
  [(:src-ip packet) (:src-port packet)
   (:dst-ip packet) (:dst-port packet)
   (:protocol packet)])

(defn get-connection
  "Get existing connection for flow"
  [packet]
  (get @connection-table (flow-key packet)))

(defn create-connection!
  "Create new connection entry"
  [packet backend]
  (let [key (flow-key packet)
        conn {:backend backend
              :created (Instant/now)
              :last-seen (Instant/now)
              :packets (AtomicLong. 0)
              :bytes (AtomicLong. 0)}]
    (swap! connection-table assoc key conn)
    conn))

(defn update-connection!
  "Update connection last-seen and stats"
  [packet]
  (when-let [conn (get @connection-table (flow-key packet))]
    (swap! connection-table update (flow-key packet)
           assoc :last-seen (Instant/now))
    (.incrementAndGet ^AtomicLong (:packets conn))
    (.addAndGet ^AtomicLong (:bytes conn) (:size packet 0))
    conn))

(defn cleanup-stale-connections!
  "Remove stale connections"
  [timeout-ms]
  (let [now (Instant/now)
        timeout (Duration/ofMillis timeout-ms)]
    (swap! connection-table
           (fn [table]
             (into {}
               (for [[k v] table
                     :when (.isBefore (.plus (:last-seen v) timeout) now)]
                 [k v]))))))

(defn get-connection-count []
  (count @connection-table))

;; ============================================================================
;; Load Balancing Algorithms
;; ============================================================================

(def rr-counter (AtomicInteger. 0))

(defn round-robin-select
  "Round-robin backend selection"
  [backends]
  (let [n (count backends)
        idx (mod (.getAndIncrement rr-counter) n)]
    (nth backends idx)))

(defn least-connections-select
  "Select backend with least connections"
  [backends]
  (apply min-key #(get-connections %) backends))

(defn weighted-round-robin-select
  "Weighted round-robin selection"
  [backends]
  (let [total-weight (reduce + (map :weight backends))
        roll (rand-int total-weight)]
    (loop [remaining backends
           cumulative 0]
      (let [backend (first remaining)
            new-cumulative (+ cumulative (:weight backend))]
        (if (< roll new-cumulative)
          backend
          (recur (rest remaining) new-cumulative))))))

(defn ip-hash-select
  "Consistent hashing based on source IP"
  [backends src-ip]
  (let [n (count backends)
        idx (mod (hash src-ip) n)]
    (nth backends idx)))

(defn response-time-select
  "Select backend with lowest response time"
  [backends]
  (apply min-key #(deref (:response-time %)) backends))

(defn select-backend
  "Select backend using configured algorithm"
  [config packet]
  (let [backends (get-healthy-backends config)
        algorithm @(:algorithm config)]
    (when (seq backends)
      (case algorithm
        :round-robin (round-robin-select backends)
        :least-conn (least-connections-select backends)
        :weighted (weighted-round-robin-select backends)
        :ip-hash (ip-hash-select backends (:src-ip packet))
        :response-time (response-time-select backends)
        (round-robin-select backends)))))

;; ============================================================================
;; Health Checking
;; ============================================================================

(def health-check-thread (atom nil))

(defn check-backend-health!
  "Perform health check on a backend"
  [backend]
  ;; Simulated health check - in reality would do TCP connect or HTTP check
  (let [healthy (> (rand) 0.05)]  ; 95% chance of being healthy
    (set-backend-health! backend healthy)
    (reset! (:last-check backend) (Instant/now))
    (when healthy
      (update-response-time! backend (+ 1 (rand-int 50))))
    healthy))

(defn start-health-checks!
  "Start background health checking"
  [config]
  (reset! health-check-thread
    (future
      (while true
        (doseq [backend @(:backends config)]
          (check-backend-health! backend))
        (Thread/sleep (:health-check-interval config))))))

(defn stop-health-checks!
  "Stop background health checking"
  []
  (when @health-check-thread
    (future-cancel @health-check-thread)
    (reset! health-check-thread nil)))

;; ============================================================================
;; Load Balancer Statistics
;; ============================================================================

(def lb-stats
  (atom {:total-requests (AtomicLong. 0)
         :redirected (AtomicLong. 0)
         :dropped (AtomicLong. 0)
         :no-backend (AtomicLong. 0)
         :by-backend {}
         :by-algorithm {}}))

(defn reset-lb-stats!
  "Reset load balancer statistics"
  []
  (.set ^AtomicLong (:total-requests @lb-stats) 0)
  (.set ^AtomicLong (:redirected @lb-stats) 0)
  (.set ^AtomicLong (:dropped @lb-stats) 0)
  (.set ^AtomicLong (:no-backend @lb-stats) 0)
  (swap! lb-stats assoc :by-backend {} :by-algorithm {}))

(defn record-lb-stats!
  "Record load balancer statistics"
  [result backend algorithm]
  (.incrementAndGet ^AtomicLong (:total-requests @lb-stats))
  (case (:action result)
    4 (.incrementAndGet ^AtomicLong (:redirected @lb-stats))  ; XDP_REDIRECT
    1 (.incrementAndGet ^AtomicLong (:dropped @lb-stats))     ; XDP_DROP
    nil)
  (when backend
    (swap! lb-stats update-in [:by-backend (:id backend)] (fnil inc 0)))
  (swap! lb-stats update-in [:by-algorithm algorithm] (fnil inc 0)))

;; ============================================================================
;; XDP Load Balancer
;; ============================================================================

(defn lb-process-packet
  "Main load balancer packet processing function"
  [config packet]
  (let [vip (:vip config)
        vport (:vport config)]

    ;; Check if packet is destined for VIP
    (if (and (= (:dst-ip packet) vip)
             (= (:dst-port packet) vport))

      ;; Check for existing connection (session persistence)
      (if-let [conn (and (:sticky-sessions config)
                         (get-connection packet))]
        ;; Use existing backend
        (let [backend (:backend conn)]
          (if (backend-healthy? backend)
            (do
              (update-connection! packet)
              (increment-connections! backend)
              (record-lb-stats! {:action XDP_REDIRECT} backend @(:algorithm config))
              {:action XDP_REDIRECT
               :backend backend
               :original-dst (:dst-ip packet)
               :new-dst (:ip backend)
               :new-port (:port backend)
               :reason :existing-connection})
            ;; Backend unhealthy, need new one
            (let [new-backend (select-backend config packet)]
              (if new-backend
                (do
                  (create-connection! packet new-backend)
                  (increment-connections! new-backend)
                  (record-lb-stats! {:action XDP_REDIRECT} new-backend @(:algorithm config))
                  {:action XDP_REDIRECT
                   :backend new-backend
                   :original-dst (:dst-ip packet)
                   :new-dst (:ip new-backend)
                   :new-port (:port new-backend)
                   :reason :backend-failover})
                (do
                  (.incrementAndGet ^AtomicLong (:no-backend @lb-stats))
                  (record-lb-stats! {:action XDP_DROP} nil @(:algorithm config))
                  {:action XDP_DROP :reason :no-healthy-backend})))))

        ;; New connection - select backend
        (let [backend (select-backend config packet)]
          (if backend
            (do
              (when (:sticky-sessions config)
                (create-connection! packet backend))
              (increment-connections! backend)
              (record-lb-stats! {:action XDP_REDIRECT} backend @(:algorithm config))
              {:action XDP_REDIRECT
               :backend backend
               :original-dst (:dst-ip packet)
               :new-dst (:ip backend)
               :new-port (:port backend)
               :reason :new-connection})
            (do
              (.incrementAndGet ^AtomicLong (:no-backend @lb-stats))
              (record-lb-stats! {:action XDP_DROP} nil @(:algorithm config))
              {:action XDP_DROP :reason :no-healthy-backend}))))

      ;; Not destined for VIP - pass through
      {:action XDP_PASS :reason :not-vip})))

;; ============================================================================
;; Packet Generation
;; ============================================================================

(defrecord Packet [src-ip dst-ip src-port dst-port protocol size timestamp])

(defn generate-client-packet
  "Generate a packet from a client to the VIP"
  [config]
  (->Packet
    (ip->int (str "10.0." (rand-int 256) "." (rand-int 256)))
    (:vip config)
    (+ 1024 (rand-int 64000))
    (:vport config)
    6  ; TCP
    (+ 64 (rand-int 1400))
    (System/nanoTime)))

(defn generate-traffic
  "Generate test traffic"
  [config n]
  (for [_ (range n)]
    (generate-client-packet config)))

;; ============================================================================
;; Statistics Display
;; ============================================================================

(defn display-lb-stats
  "Display load balancer statistics"
  [config]
  (let [stats @lb-stats]
    (println "\n=== Load Balancer Statistics ===\n")
    (println (format "Total requests:    %,d" (.get ^AtomicLong (:total-requests stats))))
    (println (format "Redirected:        %,d" (.get ^AtomicLong (:redirected stats))))
    (println (format "Dropped:           %,d" (.get ^AtomicLong (:dropped stats))))
    (println (format "No backend:        %,d" (.get ^AtomicLong (:no-backend stats))))
    (println (format "Active connections: %,d" (get-connection-count)))

    (println "\n--- Traffic Distribution ---\n")
    (println (format "%-20s %10s %10s %8s %8s %10s"
                     "Backend" "Requests" "Conns" "Weight" "Health" "Resp(ms)"))
    (println (apply str (repeat 70 "-")))
    (doseq [backend @(:backends config)]
      (let [requests (get-in stats [:by-backend (:id backend)] 0)]
        (println (format "%-20s %,10d %10d %8d %8s %10d"
                         (:id backend)
                         requests
                         (get-connections backend)
                         (:weight backend)
                         (if (backend-healthy? backend) "UP" "DOWN")
                         @(:response-time backend)))))))

(defn display-algorithm-stats
  "Display statistics by algorithm"
  []
  (let [stats @lb-stats]
    (println "\n--- By Algorithm ---\n")
    (doseq [[algo count] (sort-by val > (:by-algorithm stats))]
      (println (format "  %-15s %,d" (name algo) count)))))

;; ============================================================================
;; Exercises
;; ============================================================================

(defn exercise-weighted-distribution []
  "Exercise: Verify weighted distribution"
  (println "\n=== Exercise: Weighted Distribution ===\n")

  (let [config (create-lb-config "192.168.1.100" 80 :algorithm :weighted)]
    (add-backend! config (create-backend "web1" "10.0.0.1" 80 :weight 1))
    (add-backend! config (create-backend "web2" "10.0.0.2" 80 :weight 2))
    (add-backend! config (create-backend "web3" "10.0.0.3" 80 :weight 4))

    (reset-lb-stats!)
    (reset! connection-table {})

    ;; Generate traffic
    (println "Processing 10000 requests...")
    (let [packets (generate-traffic config 10000)]
      (doseq [packet packets]
        (lb-process-packet config packet)))

    (display-lb-stats config)

    ;; Verify distribution roughly matches weights (1:2:4)
    (let [stats @lb-stats
          web1 (get-in stats [:by-backend "web1"] 0)
          web2 (get-in stats [:by-backend "web2"] 0)
          web3 (get-in stats [:by-backend "web3"] 0)
          total (+ web1 web2 web3)]
      (println "\nExpected distribution (1:2:4):")
      (println (format "  web1: %.1f%% (expected ~14.3%%)" (* 100.0 (/ web1 total))))
      (println (format "  web2: %.1f%% (expected ~28.6%%)" (* 100.0 (/ web2 total))))
      (println (format "  web3: %.1f%% (expected ~57.1%%)" (* 100.0 (/ web3 total)))))))

(defn exercise-failover []
  "Exercise: Backend failover"
  (println "\n=== Exercise: Backend Failover ===\n")

  (let [config (create-lb-config "192.168.1.100" 80
                                 :algorithm :round-robin
                                 :sticky-sessions true)]
    (add-backend! config (create-backend "web1" "10.0.0.1" 80))
    (add-backend! config (create-backend "web2" "10.0.0.2" 80))
    (add-backend! config (create-backend "web3" "10.0.0.3" 80))

    (reset-lb-stats!)
    (reset! connection-table {})

    ;; Process some traffic normally
    (println "Phase 1: All backends healthy")
    (let [packets (generate-traffic config 100)]
      (doseq [packet packets]
        (lb-process-packet config packet)))
    (display-lb-stats config)

    ;; Mark one backend as unhealthy
    (println "\nPhase 2: Marking web2 as unhealthy")
    (let [web2 (first (filter #(= "web2" (:id %)) @(:backends config)))]
      (set-backend-health! web2 false))

    ;; Process more traffic
    (reset-lb-stats!)
    (let [packets (generate-traffic config 100)]
      (doseq [packet packets]
        (lb-process-packet config packet)))
    (display-lb-stats config)

    (println "\n(web2 should have 0 requests after failover)")))

(defn exercise-session-persistence []
  "Exercise: Session persistence"
  (println "\n=== Exercise: Session Persistence ===\n")

  (let [config (create-lb-config "192.168.1.100" 80
                                 :algorithm :round-robin
                                 :sticky-sessions true)]
    (add-backend! config (create-backend "web1" "10.0.0.1" 80))
    (add-backend! config (create-backend "web2" "10.0.0.2" 80))

    (reset-lb-stats!)
    (reset! connection-table {})

    ;; Single client making multiple requests
    (let [client-ip (ip->int "10.0.0.50")
          client-port 12345
          make-request (fn []
                         (->Packet client-ip (:vip config)
                                   client-port (:vport config)
                                   6 100 (System/nanoTime)))]

      (println "Same client making 10 requests:")
      (let [backends (for [_ (range 10)]
                       (let [result (lb-process-packet config (make-request))]
                         (:id (:backend result))))]
        (println (format "  Backends used: %s" (frequencies backends)))
        (println (format "  (Should all go to same backend with sticky sessions)"))))))

;; ============================================================================
;; Test Functions
;; ============================================================================

(defn test-backend-selection []
  (println "Testing backend selection...")

  (let [config (create-lb-config "192.168.1.100" 80)]
    (add-backend! config (create-backend "web1" "10.0.0.1" 80))
    (add-backend! config (create-backend "web2" "10.0.0.2" 80))

    ;; Test round-robin
    (set-algorithm! config :round-robin)
    (let [backends (get-healthy-backends config)
          b1 (round-robin-select backends)
          b2 (round-robin-select backends)]
      (assert (not= (:id b1) (:id b2)) "Round-robin should alternate"))

    ;; Test least connections
    (set-algorithm! config :least-conn)
    (let [backends (get-healthy-backends config)
          web1 (first (filter #(= "web1" (:id %)) backends))]
      (dotimes [_ 10] (increment-connections! web1))
      (let [selected (least-connections-select backends)]
        (assert (= "web2" (:id selected)) "Should select backend with fewer connections"))))

  (println "Backend selection tests passed!"))

(defn test-load-balancing []
  (println "Testing load balancing...")

  (let [config (create-lb-config "192.168.1.100" 80)]
    (add-backend! config (create-backend "web1" "10.0.0.1" 80))

    (reset-lb-stats!)
    (let [packet (generate-client-packet config)
          result (lb-process-packet config packet)]
      (assert (= XDP_REDIRECT (:action result)) "Should redirect to backend")
      (assert (= "web1" (:id (:backend result))) "Should select web1"))

    ;; Test no healthy backend
    (let [web1 (first @(:backends config))]
      (set-backend-health! web1 false))

    (let [packet (generate-client-packet config)
          result (lb-process-packet config packet)]
      (assert (= XDP_DROP (:action result)) "Should drop with no healthy backend")))

  (println "Load balancing tests passed!"))

(defn run-demo []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "         XDP Load Balancer Demo")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  ;; Create load balancer
  (let [config (create-lb-config "192.168.1.100" 80
                                 :algorithm :round-robin
                                 :sticky-sessions false)]
    ;; Add backends
    (add-backend! config (create-backend "web1" "10.0.0.1" 80 :weight 2))
    (add-backend! config (create-backend "web2" "10.0.0.2" 80 :weight 2))
    (add-backend! config (create-backend "web3" "10.0.0.3" 80 :weight 1))

    (reset-lb-stats!)
    (reset! connection-table {})

    ;; Test different algorithms
    (doseq [algo [:round-robin :least-conn :weighted :ip-hash]]
      (println (format "\n--- Testing %s ---" (name algo)))
      (set-algorithm! config algo)
      (reset-lb-stats!)

      (let [packets (generate-traffic config 1000)]
        (doseq [packet packets]
          (lb-process-packet config packet)))

      (display-lb-stats config))

    ;; Cleanup
    (reset! connection-table {})))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the XDP load balancer lab"
  [& args]
  (println "Lab 19.2: XDP Load Balancer")
  (println "============================\n")

  (let [command (first args)]
    (case command
      "test"
      (do
        (test-backend-selection)
        (test-load-balancing)
        (println "\nAll tests passed!"))

      "demo"
      (run-demo)

      "weighted"
      (exercise-weighted-distribution)

      "failover"
      (exercise-failover)

      "sticky"
      (exercise-session-persistence)

      ;; Default: run all
      (do
        (test-backend-selection)
        (test-load-balancing)
        (run-demo)
        (exercise-weighted-distribution)
        (exercise-failover)
        (exercise-session-persistence)

        (println "\n=== Key Takeaways ===")
        (println "1. XDP enables high-performance L4 load balancing")
        (println "2. Multiple algorithms suit different use cases")
        (println "3. Connection tracking enables session persistence")
        (println "4. Health checking ensures traffic goes to healthy backends")
        (println "5. Weighted distribution allows capacity-based routing")))))

;; Run with: clj -M -m lab-19-2-load-balancer
