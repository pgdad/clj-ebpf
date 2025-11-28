# Lab 19.2: XDP Load Balancer

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Objective

Implement a layer-4 load balancer using XDP redirect to distribute traffic across multiple backend servers.

## Prerequisites

- Completed Lab 19.1
- Understanding of load balancing concepts
- Familiarity with XDP redirect

## Part 1: Load Balancer Architecture

```clojure
(ns lab-19-2.load-balancer)

;; Backend server definition
(defrecord Backend [id ip port weight health connections])

;; Load balancer configuration
(def lb-config (atom {:backends []
                      :algorithm :round-robin
                      :health-check-interval 5000}))

;; Connection tracking
(def connection-table (atom {}))

;; Round-robin counter
(def rr-counter (atom 0))
```

## Part 2: Load Balancing Algorithms

```clojure
(defn round-robin-select [backends]
  (let [idx (swap! rr-counter #(mod (inc %) (count backends)))]
    (nth backends idx)))

(defn least-connections-select [backends]
  (apply min-key :connections backends))

(defn weighted-select [backends]
  (let [total-weight (reduce + (map :weight backends))
        roll (rand total-weight)]
    (loop [remaining backends
           cumulative 0]
      (let [backend (first remaining)
            new-cumulative (+ cumulative (:weight backend))]
        (if (< roll new-cumulative)
          backend
          (recur (rest remaining) new-cumulative))))))

(defn select-backend [backends algorithm]
  (case algorithm
    :round-robin (round-robin-select backends)
    :least-conn (least-connections-select backends)
    :weighted (weighted-select backends)
    (round-robin-select backends)))
```

## Part 3: Connection Tracking

```clojure
(defn flow-key [packet]
  [(:src-ip packet) (:dst-ip packet) (:src-port packet) (:dst-port packet)])

(defn get-or-assign-backend [packet backends algorithm]
  (let [key (flow-key packet)]
    (if-let [backend (get @connection-table key)]
      backend
      (let [selected (select-backend backends algorithm)]
        (swap! connection-table assoc key selected)
        selected))))
```

## Part 4: XDP Load Balancer

```clojure
(defn lb-process-packet [packet]
  (let [backends (filter :health (:backends @lb-config))
        algorithm (:algorithm @lb-config)]
    (when (seq backends)
      (let [backend (get-or-assign-backend packet backends algorithm)]
        {:action :redirect
         :backend backend
         :original-dst (:dst-ip packet)}))))
```

## Summary

This lab demonstrates building a layer-4 load balancer with:
- Multiple load balancing algorithms
- Connection tracking for session persistence
- Health checking for backend servers
- XDP redirect for traffic distribution
