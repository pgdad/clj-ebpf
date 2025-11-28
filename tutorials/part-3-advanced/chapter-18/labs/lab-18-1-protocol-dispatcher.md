# Lab 18.1: Protocol Dispatcher

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Objective

Build a multi-protocol packet handler using tail calls to dispatch packets to protocol-specific handlers.

## Prerequisites

- Completed Chapter 18 reading
- Understanding of network protocols
- Familiarity with tail call mechanics

## Scenario

You're building a network monitoring system that needs to handle TCP, UDP, ICMP, and other protocols with specialized handlers. Using tail calls, you'll create a modular system where new protocol handlers can be added without modifying the dispatcher.

---

## Part 1: Protocol Dispatcher Architecture

### Step 1.1: Architecture Overview

```clojure
(ns lab-18-1.protocol-dispatcher
  (:require [clojure.string :as str])
  (:import [java.time Instant]))

;; Protocol numbers (IP protocol field)
(def protocols
  {:icmp 1
   :tcp 6
   :udp 17
   :gre 47
   :icmpv6 58})

;; Architecture:
;;
;; ┌────────────┐
;; │ Dispatcher │
;; └─────┬──────┘
;;       │ tail_call(protocol)
;;       ├──────────────────────┐──────────────────────┐
;;       ▼                      ▼                      ▼
;; ┌────────────┐        ┌────────────┐        ┌────────────┐
;; │TCP Handler │        │UDP Handler │        │ICMP Handler│
;; └────────────┘        └────────────┘        └────────────┘
;;       │                      │                      │
;;       └──────────────────────┴──────────────────────┘
;;                              ▼
;;                     ┌────────────────┐
;;                     │ Shared Stats   │
;;                     │     Map        │
;;                     └────────────────┘

(println "Protocol Dispatcher Architecture")
(println "================================")
(println "Dispatcher routes packets to protocol-specific handlers")
(println "using tail calls. Each handler updates shared statistics.")
```

### Step 1.2: Mock Infrastructure

```clojure
;; Simulated BPF program array
(def prog-array (atom {}))

;; Simulated shared statistics
(def stats-map (atom {}))

;; Simulated packet
(defrecord Packet [protocol src-ip dst-ip src-port dst-port payload-size])

(defn generate-packet [protocol]
  (->Packet protocol
            (str (rand-int 256) "." (rand-int 256) "."
                 (rand-int 256) "." (rand-int 256))
            (str (rand-int 256) "." (rand-int 256) "."
                 (rand-int 256) "." (rand-int 256))
            (+ 1024 (rand-int 64000))
            (case protocol
              6 (rand-nth [80 443 8080 22])
              17 (rand-nth [53 123 161])
              80)
            (rand-int 1500)))

(defn init-stats! []
  (reset! stats-map
    {:tcp {:packets 0 :bytes 0}
     :udp {:packets 0 :bytes 0}
     :icmp {:packets 0 :bytes 0}
     :other {:packets 0 :bytes 0}
     :total {:packets 0 :bytes 0}}))
```

---

## Part 2: Protocol Handlers

### Step 2.1: Base Handler Interface

```clojure
(defprotocol IProtocolHandler
  (handle-packet [this packet])
  (get-protocol-id [this])
  (get-handler-name [this]))

(defn update-stats! [protocol-key packet]
  (swap! stats-map update-in [protocol-key :packets] inc)
  (swap! stats-map update-in [protocol-key :bytes] + (:payload-size packet))
  (swap! stats-map update-in [:total :packets] inc)
  (swap! stats-map update-in [:total :bytes] + (:payload-size packet)))
```

### Step 2.2: TCP Handler

```clojure
(def tcp-flags
  {:syn 0x02
   :ack 0x10
   :fin 0x01
   :rst 0x04
   :psh 0x08})

(defrecord TCPHandler [config]
  IProtocolHandler
  (handle-packet [this packet]
    (let [result {:protocol :tcp
                  :src-port (:src-port packet)
                  :dst-port (:dst-port packet)
                  :analysis (cond
                              (= 80 (:dst-port packet)) :http
                              (= 443 (:dst-port packet)) :https
                              (= 22 (:dst-port packet)) :ssh
                              :else :other-tcp)}]
      (update-stats! :tcp packet)
      result))

  (get-protocol-id [this] (:tcp protocols))
  (get-handler-name [this] "TCP Handler"))

(defn create-tcp-handler [config]
  (->TCPHandler config))
```

### Step 2.3: UDP Handler

```clojure
(defrecord UDPHandler [config]
  IProtocolHandler
  (handle-packet [this packet]
    (let [result {:protocol :udp
                  :src-port (:src-port packet)
                  :dst-port (:dst-port packet)
                  :analysis (cond
                              (= 53 (:dst-port packet)) :dns
                              (= 123 (:dst-port packet)) :ntp
                              (= 161 (:dst-port packet)) :snmp
                              :else :other-udp)}]
      (update-stats! :udp packet)
      result))

  (get-protocol-id [this] (:udp protocols))
  (get-handler-name [this] "UDP Handler"))

(defn create-udp-handler [config]
  (->UDPHandler config))
```

### Step 2.4: ICMP Handler

```clojure
(def icmp-types
  {0 :echo-reply
   8 :echo-request
   3 :destination-unreachable
   11 :time-exceeded})

(defrecord ICMPHandler [config]
  IProtocolHandler
  (handle-packet [this packet]
    (let [result {:protocol :icmp
                  :type (rand-nth (vals icmp-types))
                  :analysis :ping-traffic}]
      (update-stats! :icmp packet)
      result))

  (get-protocol-id [this] (:icmp protocols))
  (get-handler-name [this] "ICMP Handler"))

(defn create-icmp-handler [config]
  (->ICMPHandler config))
```

### Step 2.5: Default Handler

```clojure
(defrecord DefaultHandler [config]
  IProtocolHandler
  (handle-packet [this packet]
    (let [result {:protocol :other
                  :protocol-number (:protocol packet)
                  :analysis :unknown-protocol}]
      (update-stats! :other packet)
      result))

  (get-protocol-id [this] 0)  ; Catch-all
  (get-handler-name [this] "Default Handler"))

(defn create-default-handler [config]
  (->DefaultHandler config))
```

---

## Part 3: Dispatcher Implementation

### Step 3.1: Protocol Dispatcher

```clojure
(defrecord ProtocolDispatcher [handlers default-handler])

(defn create-dispatcher []
  (let [handlers (atom {})
        default (create-default-handler {})]
    (->ProtocolDispatcher handlers default)))

(defn register-handler! [dispatcher protocol-id handler]
  (swap! (:handlers dispatcher) assoc protocol-id handler)
  (swap! prog-array assoc protocol-id handler)
  (println (format "Registered %s for protocol %d"
                   (get-handler-name handler)
                   protocol-id)))

(defn unregister-handler! [dispatcher protocol-id]
  (swap! (:handlers dispatcher) dissoc protocol-id)
  (swap! prog-array dissoc protocol-id)
  (println (format "Unregistered handler for protocol %d" protocol-id)))

(defn dispatch-packet [dispatcher packet]
  "Simulate tail call dispatch"
  (let [protocol-id (:protocol packet)
        handler (or (get @(:handlers dispatcher) protocol-id)
                    (:default-handler dispatcher))]
    ;; Simulate tail call
    (handle-packet handler packet)))
```

### Step 3.2: Batch Processing

```clojure
(defn process-packets [dispatcher packets]
  "Process multiple packets through dispatcher"
  (let [results (atom [])]
    (doseq [packet packets]
      (let [result (dispatch-packet dispatcher packet)]
        (swap! results conj result)))
    @results))

(defn generate-traffic [num-packets protocol-distribution]
  "Generate packets according to distribution"
  (for [_ (range num-packets)]
    (let [roll (rand)
          protocol (cond
                     (< roll (:tcp protocol-distribution)) (:tcp protocols)
                     (< roll (+ (:tcp protocol-distribution)
                                (:udp protocol-distribution))) (:udp protocols)
                     (< roll (+ (:tcp protocol-distribution)
                                (:udp protocol-distribution)
                                (:icmp protocol-distribution))) (:icmp protocols)
                     :else 99)]  ; Unknown protocol
      (generate-packet protocol))))
```

---

## Part 4: Statistics and Monitoring

### Step 4.1: Statistics Display

```clojure
(defn display-stats []
  (println "\n=== Protocol Statistics ===\n")
  (println (format "%-10s %12s %15s %10s"
                   "Protocol" "Packets" "Bytes" "Avg Size"))
  (println (apply str (repeat 50 "-")))

  (doseq [proto [:tcp :udp :icmp :other :total]]
    (let [stats (get @stats-map proto)]
      (println (format "%-10s %12d %15d %10.1f"
                       (str/upper-case (name proto))
                       (:packets stats)
                       (:bytes stats)
                       (if (pos? (:packets stats))
                         (/ (double (:bytes stats)) (:packets stats))
                         0.0))))))

(defn display-distribution []
  (let [total (get-in @stats-map [:total :packets])]
    (when (pos? total)
      (println "\n=== Protocol Distribution ===\n")
      (doseq [proto [:tcp :udp :icmp :other]]
        (let [count (get-in @stats-map [proto :packets])
              pct (* 100.0 (/ count total))]
          (println (format "%-10s %5.1f%% %s"
                           (name proto)
                           pct
                           (apply str (repeat (int (/ pct 2)) "#")))))))))
```

### Step 4.2: Rate Monitoring

```clojure
(defn measure-throughput [dispatcher duration-ms packet-rate]
  "Measure dispatcher throughput"
  (let [start-time (System/currentTimeMillis)
        packets-processed (atom 0)
        distribution {:tcp 0.6 :udp 0.3 :icmp 0.08}]

    ;; Process packets for duration
    (while (< (- (System/currentTimeMillis) start-time) duration-ms)
      (let [packet (first (generate-traffic 1 distribution))]
        (dispatch-packet dispatcher packet)
        (swap! packets-processed inc)))

    (let [elapsed-ms (- (System/currentTimeMillis) start-time)
          rate (/ (* @packets-processed 1000.0) elapsed-ms)]
      {:packets @packets-processed
       :duration-ms elapsed-ms
       :rate-per-sec rate})))
```

---

## Part 5: Dynamic Handler Management

### Step 5.1: Hot Add/Remove Handlers

```clojure
(defn demonstrate-hot-update [dispatcher]
  (println "\n=== Hot Update Demonstration ===\n")

  ;; Generate some traffic
  (let [packets (generate-traffic 100 {:tcp 0.5 :udp 0.3 :icmp 0.2})]
    (println "Processing 100 packets with all handlers...")
    (process-packets dispatcher packets)
    (display-stats))

  ;; Remove TCP handler
  (println "\nRemoving TCP handler...")
  (unregister-handler! dispatcher (:tcp protocols))

  ;; Generate more traffic
  (init-stats!)
  (let [packets (generate-traffic 100 {:tcp 0.5 :udp 0.3 :icmp 0.2})]
    (println "Processing 100 packets without TCP handler...")
    (process-packets dispatcher packets)
    (display-stats))

  ;; Re-add TCP handler
  (println "\nRe-adding TCP handler...")
  (register-handler! dispatcher (:tcp protocols) (create-tcp-handler {}))

  ;; Final traffic
  (init-stats!)
  (let [packets (generate-traffic 100 {:tcp 0.5 :udp 0.3 :icmp 0.2})]
    (println "Processing 100 packets with restored TCP handler...")
    (process-packets dispatcher packets)
    (display-stats)))
```

### Step 5.2: Handler Chaining

```clojure
(defrecord ChainedHandler [handlers name]
  IProtocolHandler
  (handle-packet [this packet]
    (reduce
      (fn [result handler]
        (merge result (handle-packet handler packet)))
      {}
      handlers))

  (get-protocol-id [this] nil)
  (get-handler-name [this] name))

(defn create-chained-handler [handlers name]
  (->ChainedHandler handlers name))

(defn demonstrate-chaining []
  (println "\n=== Handler Chaining ===\n")
  (let [logger (reify IProtocolHandler
                 (handle-packet [_ packet]
                   (println (format "LOG: %s packet from %s"
                                    (name (get (clojure.set/map-invert protocols)
                                               (:protocol packet)
                                               :unknown))
                                    (:src-ip packet)))
                   {:logged true})
                 (get-handler-name [_] "Logger"))
        tcp-handler (create-tcp-handler {})
        chained (create-chained-handler [logger tcp-handler] "Logged TCP")]

    (let [packet (generate-packet (:tcp protocols))]
      (println "Processing with chained handler:")
      (println (handle-packet chained packet)))))
```

---

## Part 6: Exercises

### Exercise 1: Custom Protocol Handler

Implement a handler for GRE (protocol 47):

```clojure
(defn exercise-gre-handler []
  ;; TODO: Implement GRE handler
  ;; 1. Parse GRE header fields
  ;; 2. Track encapsulated protocol statistics
  ;; 3. Register with dispatcher
  )
```

### Exercise 2: Priority Dispatch

Implement priority-based dispatch:

```clojure
(defn exercise-priority-dispatch []
  ;; TODO: Implement priority dispatch
  ;; 1. Assign priorities to handlers
  ;; 2. Process in priority order
  ;; 3. First matching handler wins
  )
```

### Exercise 3: Rate Limiting per Protocol

Add per-protocol rate limiting:

```clojure
(defn exercise-rate-limiting []
  ;; TODO: Implement rate limiting
  ;; 1. Track packets per second per protocol
  ;; 2. Drop packets exceeding limit
  ;; 3. Report dropped packets
  )
```

---

## Part 7: Testing Your Implementation

### Test Script

```clojure
(defn test-handler-registration []
  (println "Testing handler registration...")
  (let [dispatcher (create-dispatcher)]
    (register-handler! dispatcher (:tcp protocols) (create-tcp-handler {}))
    (assert (= 1 (count @(:handlers dispatcher))) "Should have 1 handler")

    (register-handler! dispatcher (:udp protocols) (create-udp-handler {}))
    (assert (= 2 (count @(:handlers dispatcher))) "Should have 2 handlers")

    (unregister-handler! dispatcher (:tcp protocols))
    (assert (= 1 (count @(:handlers dispatcher))) "Should have 1 handler")

    (println "Handler registration tests passed!")))

(defn test-packet-dispatch []
  (println "Testing packet dispatch...")
  (init-stats!)
  (let [dispatcher (create-dispatcher)]
    (register-handler! dispatcher (:tcp protocols) (create-tcp-handler {}))
    (register-handler! dispatcher (:udp protocols) (create-udp-handler {}))

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
      (assert (= :other (:protocol result)) "Should use default"))

    (println "Packet dispatch tests passed!")))

(defn run-all-tests []
  (println "\nLab 18.1: Protocol Dispatcher")
  (println "=============================\n")

  (test-handler-registration)
  (test-packet-dispatch)

  ;; Full demo
  (println "\n=== Full Demonstration ===\n")
  (init-stats!)

  (let [dispatcher (create-dispatcher)]
    ;; Register handlers
    (register-handler! dispatcher (:tcp protocols) (create-tcp-handler {}))
    (register-handler! dispatcher (:udp protocols) (create-udp-handler {}))
    (register-handler! dispatcher (:icmp protocols) (create-icmp-handler {}))

    ;; Process traffic
    (let [packets (generate-traffic 1000 {:tcp 0.5 :udp 0.3 :icmp 0.15})]
      (println "\nProcessing 1000 packets...")
      (process-packets dispatcher packets))

    (display-stats)
    (display-distribution)

    ;; Measure throughput
    (println "\nMeasuring throughput...")
    (let [result (measure-throughput dispatcher 1000 10000)]
      (println (format "Throughput: %.0f packets/sec" (:rate-per-sec result))))

    ;; Hot update demo
    (demonstrate-hot-update dispatcher)

    ;; Chaining demo
    (demonstrate-chaining))

  (println "\n=== All Tests Complete ==="))
```

---

## Summary

In this lab you learned:
- Building a modular protocol dispatcher with tail call semantics
- Implementing protocol-specific handlers
- Hot-adding and removing handlers at runtime
- Measuring dispatcher throughput
- Handler chaining for composable processing

## Next Steps

- Try Lab 18.2 to learn about pipeline architectures
- Implement additional protocol handlers
- Add filtering and rate limiting capabilities
