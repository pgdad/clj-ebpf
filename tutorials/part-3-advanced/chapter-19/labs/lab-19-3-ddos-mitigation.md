# Lab 19.3: XDP DDoS Mitigation

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Objective

Create a DDoS mitigation system using XDP rate limiting and traffic analysis.

## Prerequisites

- Completed Labs 19.1 and 19.2
- Understanding of DDoS attack patterns
- Familiarity with rate limiting

## Part 1: Attack Detection

```clojure
(ns lab-19-3.ddos-mitigation)

;; Rate tracking
(def rate-tracker (atom {}))

;; Thresholds
(def thresholds
  {:pps-per-ip 10000
   :syn-rate 1000
   :new-conn-rate 5000})

(defn track-rate [src-ip]
  (let [now (System/currentTimeMillis)
        window-start (- now 1000)]
    (swap! rate-tracker
           (fn [tracker]
             (let [ip-data (get tracker src-ip {:timestamps []})
                   filtered (filter #(> % window-start) (:timestamps ip-data))
                   updated (conj filtered now)]
               (assoc tracker src-ip {:timestamps (vec updated)
                                      :rate (count updated)}))))))

(defn check-rate-limit [src-ip threshold]
  (let [data (get @rate-tracker src-ip {:rate 0})]
    (> (:rate data) threshold)))
```

## Part 2: SYN Flood Protection

```clojure
(def syn-cookie-enabled (atom false))

(defn detect-syn-flood [packet]
  (and (= 6 (:protocol packet))
       (:syn-flag packet)
       (not (:ack-flag packet))
       (check-rate-limit (:src-ip packet) (:syn-rate thresholds))))

(defn generate-syn-cookie [packet]
  (hash [(:src-ip packet) (:dst-ip packet)
         (:src-port packet) (:dst-port packet)
         (System/currentTimeMillis)]))
```

## Part 3: Mitigation Actions

```clojure
(def blacklist (atom #{}))
(def graylist (atom {}))

(defn add-to-blacklist! [ip duration-ms]
  (swap! blacklist conj ip)
  (future
    (Thread/sleep duration-ms)
    (swap! blacklist disj ip)))

(defn mitigate-packet [packet]
  (cond
    (contains? @blacklist (:src-ip packet))
    {:action :drop :reason :blacklisted}

    (check-rate-limit (:src-ip packet) (:pps-per-ip thresholds))
    (do
      (add-to-blacklist! (:src-ip packet) 60000)
      {:action :drop :reason :rate-exceeded})

    (detect-syn-flood packet)
    {:action :challenge :method :syn-cookie}

    :else
    {:action :pass}))
```

## Summary

This lab covers DDoS mitigation techniques including:
- Rate limiting per source IP
- SYN flood detection and mitigation
- Automatic blacklisting
- Traffic analysis patterns
