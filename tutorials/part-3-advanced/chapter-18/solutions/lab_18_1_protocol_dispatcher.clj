;; Lab 18.1 Solution: Protocol Dispatcher
;; Build a multi-protocol packet handler using tail calls
;;
;; Learning Goals:
;; - Build a modular protocol dispatcher
;; - Implement protocol-specific handlers
;; - Hot-add and remove handlers at runtime
;; - Measure dispatcher throughput

(ns lab-18-1-protocol-dispatcher
  (:require [clojure.string :as str]
            [clojure.set :as cset])
  (:import [java.time Instant]
           [java.util UUID]
           [java.util.concurrent.atomic AtomicLong]))

;; ============================================================================
;; Protocol Definitions
;; ============================================================================

(def protocols
  "IP protocol numbers"
  {:icmp   1
   :tcp    6
   :udp    17
   :gre    47
   :icmpv6 58})

(def protocol-names
  "Reverse mapping for display"
  (cset/map-invert protocols))

;; ============================================================================
;; Simulated BPF Infrastructure
;; ============================================================================

(def prog-array
  "Simulated BPF_MAP_TYPE_PROG_ARRAY for tail calls"
  (atom {}))

(def stats-map
  "Shared statistics across all handlers"
  (atom {}))

(defn init-stats!
  "Initialize statistics"
  []
  (reset! stats-map
    {:tcp   {:packets (AtomicLong. 0) :bytes (AtomicLong. 0)}
     :udp   {:packets (AtomicLong. 0) :bytes (AtomicLong. 0)}
     :icmp  {:packets (AtomicLong. 0) :bytes (AtomicLong. 0)}
     :gre   {:packets (AtomicLong. 0) :bytes (AtomicLong. 0)}
     :other {:packets (AtomicLong. 0) :bytes (AtomicLong. 0)}
     :total {:packets (AtomicLong. 0) :bytes (AtomicLong. 0)}}))

(defn update-stats!
  "Update statistics for a protocol"
  [protocol-key packet-size]
  (when-let [proto-stats (get @stats-map protocol-key)]
    (.incrementAndGet ^AtomicLong (:packets proto-stats))
    (.addAndGet ^AtomicLong (:bytes proto-stats) packet-size))
  (when-let [total-stats (get @stats-map :total)]
    (.incrementAndGet ^AtomicLong (:packets total-stats))
    (.addAndGet ^AtomicLong (:bytes total-stats) packet-size)))

(defn get-stats
  "Get current statistics"
  []
  (into {}
    (for [[k v] @stats-map]
      [k {:packets (.get ^AtomicLong (:packets v))
          :bytes (.get ^AtomicLong (:bytes v))}])))

;; ============================================================================
;; Packet Generation
;; ============================================================================

(defrecord Packet [protocol src-ip dst-ip src-port dst-port payload-size timestamp])

(defn rand-ip
  "Generate random IP address"
  []
  (str (rand-int 256) "." (rand-int 256) "."
       (rand-int 256) "." (rand-int 256)))

(defn generate-packet
  "Generate a packet with specified protocol"
  [protocol-id]
  (->Packet
    protocol-id
    (rand-ip)
    (rand-ip)
    (+ 1024 (rand-int 64000))
    (case protocol-id
      6  (rand-nth [80 443 8080 22 25])  ; TCP ports
      17 (rand-nth [53 123 161 500])      ; UDP ports
      (rand-int 65536))
    (+ 64 (rand-int 1400))
    (System/nanoTime)))

(defn generate-traffic
  "Generate packets according to protocol distribution"
  [num-packets distribution]
  (for [_ (range num-packets)]
    (let [roll (rand)
          tcp-thresh (:tcp distribution 0.5)
          udp-thresh (+ tcp-thresh (:udp distribution 0.3))
          icmp-thresh (+ udp-thresh (:icmp distribution 0.1))
          protocol (cond
                     (< roll tcp-thresh) (:tcp protocols)
                     (< roll udp-thresh) (:udp protocols)
                     (< roll icmp-thresh) (:icmp protocols)
                     :else 99)]
      (generate-packet protocol))))

;; ============================================================================
;; Protocol Handler Interface
;; ============================================================================

(defprotocol IProtocolHandler
  "Interface for protocol-specific handlers"
  (handle-packet [this packet])
  (get-protocol-id [this])
  (get-handler-name [this]))

;; ============================================================================
;; TCP Handler
;; ============================================================================

(def tcp-well-known-ports
  "Well-known TCP ports"
  {20   :ftp-data
   21   :ftp-control
   22   :ssh
   23   :telnet
   25   :smtp
   53   :dns
   80   :http
   110  :pop3
   143  :imap
   443  :https
   465  :smtps
   587  :submission
   993  :imaps
   995  :pop3s
   3306 :mysql
   5432 :postgresql
   6379 :redis
   8080 :http-alt
   8443 :https-alt})

(defrecord TCPHandler [id config stats]
  IProtocolHandler
  (handle-packet [this packet]
    (let [dst-port (:dst-port packet)
          service (get tcp-well-known-ports dst-port :unknown)
          result {:protocol :tcp
                  :src-port (:src-port packet)
                  :dst-port dst-port
                  :service service
                  :timestamp (System/currentTimeMillis)}]
      (update-stats! :tcp (:payload-size packet))

      ;; Track per-service stats
      (swap! (:stats this) update service (fnil inc 0))

      result))

  (get-protocol-id [this] (:tcp protocols))
  (get-handler-name [this] "TCP Handler"))

(defn create-tcp-handler
  "Create a new TCP handler"
  [config]
  (->TCPHandler (str (UUID/randomUUID)) config (atom {})))

;; ============================================================================
;; UDP Handler
;; ============================================================================

(def udp-well-known-ports
  "Well-known UDP ports"
  {53   :dns
   67   :dhcp-server
   68   :dhcp-client
   69   :tftp
   123  :ntp
   137  :netbios-ns
   138  :netbios-dgm
   161  :snmp
   162  :snmp-trap
   500  :isakmp
   514  :syslog
   520  :rip
   1194 :openvpn
   4500 :ipsec-nat-t})

(defrecord UDPHandler [id config stats]
  IProtocolHandler
  (handle-packet [this packet]
    (let [dst-port (:dst-port packet)
          service (get udp-well-known-ports dst-port :unknown)
          result {:protocol :udp
                  :src-port (:src-port packet)
                  :dst-port dst-port
                  :service service
                  :timestamp (System/currentTimeMillis)}]
      (update-stats! :udp (:payload-size packet))
      (swap! (:stats this) update service (fnil inc 0))
      result))

  (get-protocol-id [this] (:udp protocols))
  (get-handler-name [this] "UDP Handler"))

(defn create-udp-handler
  "Create a new UDP handler"
  [config]
  (->UDPHandler (str (UUID/randomUUID)) config (atom {})))

;; ============================================================================
;; ICMP Handler
;; ============================================================================

(def icmp-types
  "ICMP message types"
  {0  :echo-reply
   3  :destination-unreachable
   4  :source-quench
   5  :redirect
   8  :echo-request
   9  :router-advertisement
   10 :router-solicitation
   11 :time-exceeded
   12 :parameter-problem
   13 :timestamp-request
   14 :timestamp-reply})

(defrecord ICMPHandler [id config stats]
  IProtocolHandler
  (handle-packet [this packet]
    (let [icmp-type (rand-int 15)
          type-name (get icmp-types icmp-type :unknown)
          result {:protocol :icmp
                  :type icmp-type
                  :type-name type-name
                  :timestamp (System/currentTimeMillis)}]
      (update-stats! :icmp (:payload-size packet))
      (swap! (:stats this) update type-name (fnil inc 0))
      result))

  (get-protocol-id [this] (:icmp protocols))
  (get-handler-name [this] "ICMP Handler"))

(defn create-icmp-handler
  "Create a new ICMP handler"
  [config]
  (->ICMPHandler (str (UUID/randomUUID)) config (atom {})))

;; ============================================================================
;; GRE Handler
;; ============================================================================

(defrecord GREHandler [id config stats]
  IProtocolHandler
  (handle-packet [this packet]
    (let [encapsulated-protocol (rand-nth [4 6 17 47]) ; Simulated inner protocol
          result {:protocol :gre
                  :encapsulated-protocol encapsulated-protocol
                  :encapsulated-name (get protocol-names encapsulated-protocol :unknown)
                  :timestamp (System/currentTimeMillis)}]
      (update-stats! :gre (:payload-size packet))
      (swap! (:stats this) update (:encapsulated-name result) (fnil inc 0))
      result))

  (get-protocol-id [this] (:gre protocols))
  (get-handler-name [this] "GRE Handler"))

(defn create-gre-handler
  "Create a new GRE handler"
  [config]
  (->GREHandler (str (UUID/randomUUID)) config (atom {})))

;; ============================================================================
;; Default Handler
;; ============================================================================

(defrecord DefaultHandler [id config]
  IProtocolHandler
  (handle-packet [this packet]
    (let [result {:protocol :other
                  :protocol-number (:protocol packet)
                  :timestamp (System/currentTimeMillis)}]
      (update-stats! :other (:payload-size packet))
      result))

  (get-protocol-id [this] 0)
  (get-handler-name [this] "Default Handler"))

(defn create-default-handler
  "Create a default (catch-all) handler"
  [config]
  (->DefaultHandler (str (UUID/randomUUID)) config))

;; ============================================================================
;; Protocol Dispatcher
;; ============================================================================

(defrecord ProtocolDispatcher [handlers default-handler dispatch-stats])

(defn create-dispatcher
  "Create a new protocol dispatcher"
  []
  (let [handlers (atom {})
        default (create-default-handler {})]
    (->ProtocolDispatcher
      handlers
      default
      (atom {:dispatches 0 :tail-calls 0 :default-fallbacks 0}))))

(defn register-handler!
  "Register a handler for a protocol"
  [dispatcher protocol-id handler]
  (swap! (:handlers dispatcher) assoc protocol-id handler)
  (swap! prog-array assoc protocol-id handler)
  (println (format "Registered %s for protocol %d (%s)"
                   (get-handler-name handler)
                   protocol-id
                   (get protocol-names protocol-id "unknown"))))

(defn unregister-handler!
  "Unregister a handler for a protocol"
  [dispatcher protocol-id]
  (let [handler (get @(:handlers dispatcher) protocol-id)]
    (swap! (:handlers dispatcher) dissoc protocol-id)
    (swap! prog-array dissoc protocol-id)
    (when handler
      (println (format "Unregistered %s for protocol %d"
                       (get-handler-name handler)
                       protocol-id)))))

(defn dispatch-packet
  "Dispatch a packet to the appropriate handler (simulates tail call)"
  [dispatcher packet]
  (swap! (:dispatch-stats dispatcher) update :dispatches inc)

  (let [protocol-id (:protocol packet)
        handler (get @(:handlers dispatcher) protocol-id)]
    (if handler
      (do
        (swap! (:dispatch-stats dispatcher) update :tail-calls inc)
        (handle-packet handler packet))
      (do
        (swap! (:dispatch-stats dispatcher) update :default-fallbacks inc)
        (handle-packet (:default-handler dispatcher) packet)))))

(defn get-dispatch-stats
  "Get dispatcher statistics"
  [dispatcher]
  @(:dispatch-stats dispatcher))

;; ============================================================================
;; Batch Processing
;; ============================================================================

(defn process-packets
  "Process multiple packets through the dispatcher"
  [dispatcher packets]
  (doall (map #(dispatch-packet dispatcher %) packets)))

;; ============================================================================
;; Statistics Display
;; ============================================================================

(defn display-stats
  "Display protocol statistics"
  []
  (println "\n=== Protocol Statistics ===\n")
  (println (format "%-10s %12s %15s %10s"
                   "Protocol" "Packets" "Bytes" "Avg Size"))
  (println (apply str (repeat 50 "-")))

  (let [stats (get-stats)]
    (doseq [proto [:tcp :udp :icmp :gre :other :total]]
      (let [s (get stats proto)]
        (println (format "%-10s %12d %15d %10.1f"
                         (str/upper-case (name proto))
                         (:packets s)
                         (:bytes s)
                         (if (pos? (:packets s))
                           (double (/ (:bytes s) (:packets s)))
                           0.0)))))))

(defn display-distribution
  "Display protocol distribution as bar chart"
  []
  (let [stats (get-stats)
        total (get-in stats [:total :packets])]
    (when (pos? total)
      (println "\n=== Protocol Distribution ===\n")
      (doseq [proto [:tcp :udp :icmp :gre :other]]
        (let [count (get-in stats [proto :packets])
              pct (* 100.0 (/ count total))
              bar-len (int (/ pct 2))]
          (println (format "%-10s %5.1f%% %s"
                           (name proto)
                           pct
                           (apply str (repeat bar-len "#")))))))))

(defn display-dispatch-stats
  "Display dispatcher statistics"
  [dispatcher]
  (let [stats (get-dispatch-stats dispatcher)]
    (println "\n=== Dispatcher Statistics ===\n")
    (println (format "Total dispatches:    %d" (:dispatches stats)))
    (println (format "Tail calls:          %d" (:tail-calls stats)))
    (println (format "Default fallbacks:   %d" (:default-fallbacks stats)))
    (when (pos? (:dispatches stats))
      (println (format "Tail call rate:      %.1f%%"
                       (* 100.0 (/ (:tail-calls stats) (:dispatches stats))))))))

;; ============================================================================
;; Throughput Measurement
;; ============================================================================

(defn measure-throughput
  "Measure dispatcher throughput"
  [dispatcher duration-ms distribution]
  (let [start-time (System/currentTimeMillis)
        packets-processed (atom 0)
        deadline (+ start-time duration-ms)]

    (while (< (System/currentTimeMillis) deadline)
      (let [packets (generate-traffic 100 distribution)]
        (process-packets dispatcher packets)
        (swap! packets-processed + 100)))

    (let [elapsed-ms (- (System/currentTimeMillis) start-time)
          rate (/ (* @packets-processed 1000.0) elapsed-ms)]
      {:packets @packets-processed
       :duration-ms elapsed-ms
       :rate-per-sec rate})))

;; ============================================================================
;; Exercises
;; ============================================================================

(defn exercise-gre-handler
  "Exercise 1: Custom GRE protocol handler"
  []
  (println "\n=== Exercise 1: GRE Handler ===\n")

  (init-stats!)
  (let [dispatcher (create-dispatcher)
        gre-handler (create-gre-handler {})]

    ;; Register GRE handler
    (register-handler! dispatcher (:gre protocols) gre-handler)

    ;; Generate some GRE traffic
    (let [packets (for [_ (range 100)]
                    (generate-packet (:gre protocols)))]
      (process-packets dispatcher packets))

    ;; Show GRE-specific stats
    (println "\nGRE encapsulated protocol distribution:")
    (doseq [[proto count] (sort-by val > @(:stats gre-handler))]
      (println (format "  %s: %d" (name proto) count)))

    (display-stats)))

(defn exercise-priority-dispatch
  "Exercise 2: Priority-based dispatch"
  []
  (println "\n=== Exercise 2: Priority Dispatch ===\n")

  (let [priority-handlers (atom (sorted-map))
        add-priority-handler!
        (fn [priority handler]
          (swap! priority-handlers assoc priority handler)
          (println (format "Added %s with priority %d"
                           (get-handler-name handler) priority)))

        dispatch-with-priority
        (fn [packet]
          (some (fn [[_ handler]]
                  (when (= (get-protocol-id handler) (:protocol packet))
                    (handle-packet handler packet)))
                @priority-handlers))]

    ;; Add handlers with priorities (lower = higher priority)
    (add-priority-handler! 1 (create-tcp-handler {}))
    (add-priority-handler! 2 (create-udp-handler {}))
    (add-priority-handler! 3 (create-icmp-handler {}))

    (println "\nPriority order:")
    (doseq [[prio handler] @priority-handlers]
      (println (format "  %d: %s" prio (get-handler-name handler))))

    ;; Test dispatch
    (println "\nDispatching packets:")
    (doseq [proto [6 17 1]]
      (let [packet (generate-packet proto)
            result (dispatch-with-priority packet)]
        (println (format "  Protocol %d -> %s"
                         proto (name (:protocol result))))))))

(defn exercise-rate-limiting
  "Exercise 3: Per-protocol rate limiting"
  []
  (println "\n=== Exercise 3: Rate Limiting ===\n")

  (let [rate-limits {:tcp 100 :udp 50 :icmp 10}
        rate-counters (atom {:tcp (AtomicLong. 0)
                             :udp (AtomicLong. 0)
                             :icmp (AtomicLong. 0)})
        dropped (atom {:tcp 0 :udp 0 :icmp 0})
        window-start (atom (System/currentTimeMillis))

        check-rate-limit
        (fn [protocol-key]
          (let [now (System/currentTimeMillis)]
            ;; Reset counters every second
            (when (> (- now @window-start) 1000)
              (reset! window-start now)
              (doseq [[k v] @rate-counters]
                (.set ^AtomicLong v 0)))

            ;; Check limit
            (let [counter (get @rate-counters protocol-key)
                  limit (get rate-limits protocol-key 100)]
              (if (< (.get ^AtomicLong counter) limit)
                (do (.incrementAndGet ^AtomicLong counter) true)
                (do (swap! dropped update protocol-key inc) false)))))]

    (println "Rate limits:" rate-limits)

    ;; Generate traffic that exceeds limits
    (init-stats!)
    (let [dispatcher (create-dispatcher)]
      (register-handler! dispatcher (:tcp protocols) (create-tcp-handler {}))
      (register-handler! dispatcher (:udp protocols) (create-udp-handler {}))
      (register-handler! dispatcher (:icmp protocols) (create-icmp-handler {}))

      ;; Process with rate limiting
      (let [packets (generate-traffic 500 {:tcp 0.6 :udp 0.3 :icmp 0.1})]
        (doseq [packet packets]
          (let [proto-key (get protocol-names (:protocol packet) :other)]
            (when (check-rate-limit proto-key)
              (dispatch-packet dispatcher packet)))))

      (println "\nDropped packets:")
      (doseq [[k v] @dropped]
        (println (format "  %s: %d" (name k) v)))

      (display-stats))))

;; ============================================================================
;; Test Functions
;; ============================================================================

(defn test-handler-registration []
  (println "Testing handler registration...")

  (let [dispatcher (create-dispatcher)]
    (register-handler! dispatcher (:tcp protocols) (create-tcp-handler {}))
    (assert (= 1 (count @(:handlers dispatcher))) "Should have 1 handler")

    (register-handler! dispatcher (:udp protocols) (create-udp-handler {}))
    (assert (= 2 (count @(:handlers dispatcher))) "Should have 2 handlers")

    (unregister-handler! dispatcher (:tcp protocols))
    (assert (= 1 (count @(:handlers dispatcher))) "Should have 1 handler after unregister")

    (println "Handler registration tests passed!")))

(defn test-packet-dispatch []
  (println "Testing packet dispatch...")

  (init-stats!)
  (let [dispatcher (create-dispatcher)]
    (register-handler! dispatcher (:tcp protocols) (create-tcp-handler {}))
    (register-handler! dispatcher (:udp protocols) (create-udp-handler {}))
    (register-handler! dispatcher (:icmp protocols) (create-icmp-handler {}))

    ;; Dispatch TCP packet
    (let [packet (generate-packet (:tcp protocols))
          result (dispatch-packet dispatcher packet)]
      (assert (= :tcp (:protocol result)) "Should handle TCP"))

    ;; Dispatch UDP packet
    (let [packet (generate-packet (:udp protocols))
          result (dispatch-packet dispatcher packet)]
      (assert (= :udp (:protocol result)) "Should handle UDP"))

    ;; Dispatch unknown protocol (should use default)
    (let [packet (generate-packet 99)
          result (dispatch-packet dispatcher packet)]
      (assert (= :other (:protocol result)) "Should use default handler"))

    (println "Packet dispatch tests passed!")))

(defn test-throughput []
  (println "Testing throughput measurement...")

  (init-stats!)
  (let [dispatcher (create-dispatcher)]
    (register-handler! dispatcher (:tcp protocols) (create-tcp-handler {}))
    (register-handler! dispatcher (:udp protocols) (create-udp-handler {}))
    (register-handler! dispatcher (:icmp protocols) (create-icmp-handler {}))

    (let [result (measure-throughput dispatcher 1000
                                      {:tcp 0.5 :udp 0.3 :icmp 0.2})]
      (assert (pos? (:packets result)) "Should process packets")
      (assert (pos? (:rate-per-sec result)) "Should have positive rate")
      (println (format "Throughput: %.0f packets/sec" (:rate-per-sec result)))))

  (println "Throughput tests passed!"))

(defn run-demo []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "         Protocol Dispatcher Demo")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  (init-stats!)

  (let [dispatcher (create-dispatcher)]
    ;; Register all handlers
    (println "Registering handlers...\n")
    (register-handler! dispatcher (:tcp protocols) (create-tcp-handler {}))
    (register-handler! dispatcher (:udp protocols) (create-udp-handler {}))
    (register-handler! dispatcher (:icmp protocols) (create-icmp-handler {}))
    (register-handler! dispatcher (:gre protocols) (create-gre-handler {}))

    ;; Process traffic
    (println "\nProcessing 1000 packets...")
    (let [packets (generate-traffic 1000 {:tcp 0.5 :udp 0.3 :icmp 0.15})]
      (process-packets dispatcher packets))

    (display-stats)
    (display-distribution)
    (display-dispatch-stats dispatcher)

    ;; Measure throughput
    (println "\nMeasuring throughput...")
    (init-stats!)
    (let [result (measure-throughput dispatcher 2000 {:tcp 0.5 :udp 0.3 :icmp 0.2})]
      (println (format "Throughput: %.0f packets/sec" (:rate-per-sec result))))

    ;; Hot update demo
    (println "\n=== Hot Update Demo ===")
    (init-stats!)
    (println "\nRemoving TCP handler...")
    (unregister-handler! dispatcher (:tcp protocols))

    (let [packets (generate-traffic 100 {:tcp 0.5 :udp 0.3 :icmp 0.2})]
      (process-packets dispatcher packets))

    (println "\nAfter removing TCP handler:")
    (display-stats)

    (println "\nRe-adding TCP handler...")
    (register-handler! dispatcher (:tcp protocols) (create-tcp-handler {}))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the protocol dispatcher lab"
  [& args]
  (println "Lab 18.1: Protocol Dispatcher")
  (println "==============================\n")

  (let [command (first args)]
    (case command
      "test"
      (do
        (test-handler-registration)
        (test-packet-dispatch)
        (test-throughput)
        (println "\nAll tests passed!"))

      "demo"
      (run-demo)

      "exercise1"
      (exercise-gre-handler)

      "exercise2"
      (exercise-priority-dispatch)

      "exercise3"
      (exercise-rate-limiting)

      ;; Default: run all
      (do
        (test-handler-registration)
        (test-packet-dispatch)
        (test-throughput)
        (run-demo)
        (exercise-gre-handler)
        (exercise-priority-dispatch)
        (exercise-rate-limiting)

        (println "\n=== Key Takeaways ===")
        (println "1. Tail calls enable modular protocol handling")
        (println "2. Handlers can be added/removed at runtime")
        (println "3. Shared statistics maps enable cross-handler metrics")
        (println "4. Default handlers catch unregistered protocols")
        (println "5. Rate limiting can be applied per-protocol")))))

;; Run with: clj -M -m lab-18-1-protocol-dispatcher
