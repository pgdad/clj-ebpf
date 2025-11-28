# Lab 18.2: Pipeline Architecture

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Objective

Implement a multi-stage processing pipeline with shared state, demonstrating how BPF programs can be chained together for complex packet processing.

## Prerequisites

- Completed Lab 18.1
- Understanding of pipeline patterns
- Familiarity with shared state concepts

## Scenario

You're building a packet processing system that needs to parse, validate, transform, and route packets through multiple stages. Each stage is a separate "BPF program" that shares state with other stages through maps.

---

## Part 1: Pipeline Architecture

### Step 1.1: Core Pipeline Abstractions

```clojure
(ns lab-18-2.pipeline-architecture
  (:require [clojure.string :as str])
  (:import [java.util UUID]
           [java.time Instant]))

;; Pipeline stage interface
(defprotocol IPipelineStage
  (process [this ctx])
  (stage-name [this])
  (stage-id [this]))

;; Pipeline context - shared state between stages
(defrecord PipelineContext [packet state metadata])

(defn create-context [packet]
  (->PipelineContext packet (atom {}) (atom {:created-at (Instant/now)})))

(defn get-state [ctx key]
  (get @(:state ctx) key))

(defn set-state! [ctx key value]
  (swap! (:state ctx) assoc key value))

(defn add-metadata! [ctx key value]
  (swap! (:metadata ctx) assoc key value))
```

### Step 1.2: Pipeline Manager

```clojure
(defrecord Pipeline [stages shared-state stats])

(defn create-pipeline []
  (->Pipeline (atom [])
              (atom {})
              (atom {:processed 0
                     :passed 0
                     :dropped 0
                     :errors 0
                     :stage-times {}})))

(defn add-stage! [pipeline stage]
  (swap! (:stages pipeline) conj stage)
  (println (format "Added stage: %s (ID: %s)"
                   (stage-name stage)
                   (stage-id stage))))

(defn remove-stage! [pipeline stage-id]
  (swap! (:stages pipeline)
         (fn [stages]
           (vec (remove #(= stage-id (stage-id %)) stages)))))

(defn get-stages [pipeline]
  @(:stages pipeline))
```

---

## Part 2: Pipeline Stages

### Step 2.1: Parser Stage

```clojure
(defrecord ParserStage [id config]
  IPipelineStage
  (process [this ctx]
    (let [packet (:packet ctx)]
      ;; Parse packet headers
      (set-state! ctx :parsed
                  {:protocol (:protocol packet)
                   :src-ip (:src-ip packet)
                   :dst-ip (:dst-ip packet)
                   :src-port (:src-port packet)
                   :dst-port (:dst-port packet)
                   :size (:payload-size packet)})
      (add-metadata! ctx :parser-time (System/nanoTime))
      {:action :continue
       :stage (:id this)}))

  (stage-name [this] "Parser")
  (stage-id [this] (:id this)))

(defn create-parser-stage [config]
  (->ParserStage (str (UUID/randomUUID)) config))
```

### Step 2.2: Validator Stage

```clojure
(def validation-rules
  {:min-packet-size 20
   :max-packet-size 9000
   :blocked-ports #{23 135 139 445}
   :blocked-protocols #{}})

(defrecord ValidatorStage [id config]
  IPipelineStage
  (process [this ctx]
    (let [parsed (get-state ctx :parsed)
          rules (merge validation-rules (:rules config))]
      (cond
        ;; Check packet size
        (< (:size parsed) (:min-packet-size rules))
        (do
          (set-state! ctx :drop-reason :packet-too-small)
          {:action :drop :stage (:id this) :reason :packet-too-small})

        (> (:size parsed) (:max-packet-size rules))
        (do
          (set-state! ctx :drop-reason :packet-too-large)
          {:action :drop :stage (:id this) :reason :packet-too-large})

        ;; Check blocked ports
        (contains? (:blocked-ports rules) (:dst-port parsed))
        (do
          (set-state! ctx :drop-reason :blocked-port)
          {:action :drop :stage (:id this) :reason :blocked-port})

        ;; Check blocked protocols
        (contains? (:blocked-protocols rules) (:protocol parsed))
        (do
          (set-state! ctx :drop-reason :blocked-protocol)
          {:action :drop :stage (:id this) :reason :blocked-protocol})

        :else
        (do
          (set-state! ctx :validated true)
          (add-metadata! ctx :validator-time (System/nanoTime))
          {:action :continue :stage (:id this)}))))

  (stage-name [this] "Validator")
  (stage-id [this] (:id this)))

(defn create-validator-stage [config]
  (->ValidatorStage (str (UUID/randomUUID)) config))
```

### Step 2.3: Classifier Stage

```clojure
(def traffic-classes
  {:web #{80 443 8080 8443}
   :dns #{53}
   :ssh #{22}
   :mail #{25 465 587 993 995}
   :database #{3306 5432 27017 6379}})

(defrecord ClassifierStage [id config]
  IPipelineStage
  (process [this ctx]
    (let [parsed (get-state ctx :parsed)
          dst-port (:dst-port parsed)
          traffic-class (or (first (for [[class ports] traffic-classes
                                         :when (contains? ports dst-port)]
                                     class))
                            :other)]
      (set-state! ctx :traffic-class traffic-class)
      (set-state! ctx :priority
                  (case traffic-class
                    :dns :high
                    :ssh :high
                    :web :medium
                    :mail :low
                    :database :medium
                    :low))
      (add-metadata! ctx :classifier-time (System/nanoTime))
      {:action :continue :stage (:id this) :class traffic-class}))

  (stage-name [this] "Classifier")
  (stage-id [this] (:id this)))

(defn create-classifier-stage [config]
  (->ClassifierStage (str (UUID/randomUUID)) config))
```

### Step 2.4: Transformer Stage

```clojure
(defrecord TransformerStage [id config]
  IPipelineStage
  (process [this ctx]
    (let [parsed (get-state ctx :parsed)
          traffic-class (get-state ctx :traffic-class)
          transforms (:transforms config)]

      ;; Apply transforms based on config
      (when (:add-timestamp transforms)
        (set-state! ctx :timestamp (System/currentTimeMillis)))

      (when (:normalize-ips transforms)
        (set-state! ctx :normalized-src
                    (str/lower-case (:src-ip parsed)))
        (set-state! ctx :normalized-dst
                    (str/lower-case (:dst-ip parsed))))

      (when (:compute-hash transforms)
        (set-state! ctx :flow-hash
                    (hash [(:src-ip parsed)
                           (:dst-ip parsed)
                           (:src-port parsed)
                           (:dst-port parsed)])))

      (add-metadata! ctx :transformer-time (System/nanoTime))
      {:action :continue :stage (:id this)}))

  (stage-name [this] "Transformer")
  (stage-id [this] (:id this)))

(defn create-transformer-stage [config]
  (->TransformerStage (str (UUID/randomUUID)) config))
```

### Step 2.5: Router Stage

```clojure
(def routing-rules
  [{:match {:traffic-class :web} :output :web-queue}
   {:match {:traffic-class :dns} :output :dns-queue}
   {:match {:priority :high} :output :priority-queue}
   {:match {} :output :default-queue}])  ; Catch-all

(defrecord RouterStage [id config]
  IPipelineStage
  (process [this ctx]
    (let [traffic-class (get-state ctx :traffic-class)
          priority (get-state ctx :priority)
          current-state {:traffic-class traffic-class :priority priority}
          matching-rule (first (filter
                                 (fn [rule]
                                   (every? (fn [[k v]]
                                             (= v (get current-state k)))
                                           (:match rule)))
                                 routing-rules))
          output (or (:output matching-rule) :default-queue)]

      (set-state! ctx :output-queue output)
      (add-metadata! ctx :router-time (System/nanoTime))
      {:action :route :stage (:id this) :output output}))

  (stage-name [this] "Router")
  (stage-id [this] (:id this)))

(defn create-router-stage [config]
  (->RouterStage (str (UUID/randomUUID)) config))
```

---

## Part 3: Pipeline Execution

### Step 3.1: Pipeline Runner

```clojure
(defn run-pipeline [pipeline ctx]
  "Execute all stages in the pipeline"
  (let [stages (get-stages pipeline)
        stats (:stats pipeline)]

    (swap! stats update :processed inc)

    (loop [remaining-stages stages
           last-result nil]
      (if (empty? remaining-stages)
        ;; All stages completed
        (do
          (swap! stats update :passed inc)
          {:status :completed
           :context ctx
           :result last-result})

        ;; Process next stage
        (let [stage (first remaining-stages)
              start-time (System/nanoTime)
              result (try
                       (process stage ctx)
                       (catch Exception e
                         {:action :error
                          :stage (stage-id stage)
                          :error (.getMessage e)}))
              elapsed (- (System/nanoTime) start-time)]

          ;; Update stage timing stats
          (swap! stats update-in [:stage-times (stage-name stage)]
                 (fn [times]
                   (conj (or times []) elapsed)))

          ;; Handle result
          (case (:action result)
            :continue
            (recur (rest remaining-stages) result)

            :drop
            (do
              (swap! stats update :dropped inc)
              {:status :dropped
               :context ctx
               :result result})

            :route
            (do
              ;; Continue to remaining stages after routing decision
              (recur (rest remaining-stages) result))

            :error
            (do
              (swap! stats update :errors inc)
              {:status :error
               :context ctx
               :result result})

            ;; Unknown action, continue
            (recur (rest remaining-stages) result)))))))

(defn process-packet [pipeline packet]
  "Process a single packet through the pipeline"
  (let [ctx (create-context packet)]
    (run-pipeline pipeline ctx)))
```

### Step 3.2: Batch Processing

```clojure
(defn process-batch [pipeline packets]
  "Process multiple packets through the pipeline"
  (let [results (atom {:completed [] :dropped [] :errors []})]
    (doseq [packet packets]
      (let [result (process-packet pipeline packet)]
        (case (:status result)
          :completed (swap! results update :completed conj result)
          :dropped (swap! results update :dropped conj result)
          :error (swap! results update :errors conj result)
          nil)))
    @results))
```

---

## Part 4: Statistics and Monitoring

### Step 4.1: Pipeline Statistics

```clojure
(defn get-pipeline-stats [pipeline]
  (let [stats @(:stats pipeline)
        stage-times (:stage-times stats)]
    {:processed (:processed stats)
     :passed (:passed stats)
     :dropped (:dropped stats)
     :errors (:errors stats)
     :pass-rate (if (pos? (:processed stats))
                  (* 100.0 (/ (:passed stats) (:processed stats)))
                  0.0)
     :drop-rate (if (pos? (:processed stats))
                  (* 100.0 (/ (:dropped stats) (:processed stats)))
                  0.0)
     :avg-stage-times (into {}
                        (for [[stage times] stage-times]
                          [stage (if (seq times)
                                   (/ (reduce + times) (count times) 1000.0)
                                   0.0)]))}))

(defn display-pipeline-stats [pipeline]
  (let [stats (get-pipeline-stats pipeline)]
    (println "\n=== Pipeline Statistics ===\n")
    (println (format "Processed:  %d" (:processed stats)))
    (println (format "Passed:     %d (%.1f%%)" (:passed stats) (:pass-rate stats)))
    (println (format "Dropped:    %d (%.1f%%)" (:dropped stats) (:drop-rate stats)))
    (println (format "Errors:     %d" (:errors stats)))

    (println "\nAverage Stage Times (microseconds):")
    (doseq [[stage avg-time] (sort-by key (:avg-stage-times stats))]
      (println (format "  %-15s %.2f μs" stage avg-time)))))
```

### Step 4.2: Output Queue Statistics

```clojure
(def output-queues (atom {}))

(defn record-output [output-queue ctx]
  (swap! output-queues update output-queue
         (fn [q]
           (update (or q {:count 0 :bytes 0})
                   :count inc)))
  (swap! output-queues update-in [output-queue :bytes]
         + (get-in @(:state ctx) [:parsed :size] 0)))

(defn display-queue-stats []
  (println "\n=== Output Queue Statistics ===\n")
  (println (format "%-20s %10s %15s" "Queue" "Packets" "Bytes"))
  (println (apply str (repeat 48 "-")))
  (doseq [[queue stats] (sort-by key @output-queues)]
    (println (format "%-20s %10d %15d"
                     (name queue)
                     (:count stats)
                     (:bytes stats)))))
```

---

## Part 5: Complete Pipeline Example

### Step 5.1: Build and Run Pipeline

```clojure
(defn create-full-pipeline []
  (let [pipeline (create-pipeline)]
    ;; Add stages in order
    (add-stage! pipeline (create-parser-stage {}))
    (add-stage! pipeline (create-validator-stage
                           {:rules {:blocked-ports #{23}}}))
    (add-stage! pipeline (create-classifier-stage {}))
    (add-stage! pipeline (create-transformer-stage
                           {:transforms {:add-timestamp true
                                        :normalize-ips true
                                        :compute-hash true}}))
    (add-stage! pipeline (create-router-stage {}))
    pipeline))

(defn generate-test-packets [n]
  (for [_ (range n)]
    {:protocol (rand-nth [6 17 1])
     :src-ip (str (rand-int 256) "." (rand-int 256) "."
                  (rand-int 256) "." (rand-int 256))
     :dst-ip (str (rand-int 256) "." (rand-int 256) "."
                  (rand-int 256) "." (rand-int 256))
     :src-port (+ 1024 (rand-int 64000))
     :dst-port (rand-nth [80 443 53 22 25 3306 8080 12345])
     :payload-size (+ 64 (rand-int 1400))}))

(defn run-full-demo []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "         Pipeline Architecture Demo")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  (reset! output-queues {})

  (let [pipeline (create-full-pipeline)
        packets (generate-test-packets 1000)]

    (println "\nProcessing 1000 packets...\n")

    (doseq [packet packets]
      (let [result (process-packet pipeline packet)]
        (when (= :completed (:status result))
          (let [ctx (:context result)
                output (get-state ctx :output-queue)]
            (record-output output ctx)))))

    (display-pipeline-stats pipeline)
    (display-queue-stats)))
```

---

## Part 6: Exercises

### Exercise 1: Rate Limiting Stage

Add a rate limiting stage:

```clojure
(defn exercise-rate-limiter []
  ;; TODO: Implement rate limiting stage
  ;; 1. Track packets per second per source IP
  ;; 2. Drop packets exceeding limit
  ;; 3. Support burst allowance
  )
```

### Exercise 2: Deduplication Stage

Implement packet deduplication:

```clojure
(defn exercise-deduplication []
  ;; TODO: Implement deduplication stage
  ;; 1. Track recent packet hashes
  ;; 2. Drop duplicates within time window
  ;; 3. Report duplicate statistics
  )
```

### Exercise 3: Dynamic Stage Configuration

Allow runtime stage configuration updates:

```clojure
(defn exercise-dynamic-config []
  ;; TODO: Implement dynamic configuration
  ;; 1. Allow updating stage config at runtime
  ;; 2. Support hot-reload of validation rules
  ;; 3. Track configuration versions
  )
```

---

## Part 7: Testing Your Implementation

### Test Script

```clojure
(defn test-pipeline-creation []
  (println "Testing pipeline creation...")
  (let [pipeline (create-pipeline)]
    (assert (empty? (get-stages pipeline)) "Should start empty")
    (add-stage! pipeline (create-parser-stage {}))
    (assert (= 1 (count (get-stages pipeline))) "Should have 1 stage")
    (println "Pipeline creation tests passed!")))

(defn test-stage-processing []
  (println "Testing stage processing...")
  (let [parser (create-parser-stage {})
        packet {:protocol 6 :src-ip "1.2.3.4" :dst-ip "5.6.7.8"
                :src-port 12345 :dst-port 80 :payload-size 100}
        ctx (create-context packet)]

    (let [result (process parser ctx)]
      (assert (= :continue (:action result)) "Parser should continue")
      (assert (some? (get-state ctx :parsed)) "Should have parsed state"))

    (println "Stage processing tests passed!")))

(defn test-full-pipeline []
  (println "Testing full pipeline...")
  (let [pipeline (create-full-pipeline)
        packet {:protocol 6 :src-ip "1.2.3.4" :dst-ip "5.6.7.8"
                :src-port 12345 :dst-port 80 :payload-size 100}]

    (let [result (process-packet pipeline packet)]
      (assert (= :completed (:status result)) "Should complete")
      (assert (= :web-queue (get-state (:context result) :output-queue))
              "Should route to web queue"))

    (println "Full pipeline tests passed!")))

(defn run-all-tests []
  (println "\nLab 18.2: Pipeline Architecture")
  (println "================================\n")

  (test-pipeline-creation)
  (test-stage-processing)
  (test-full-pipeline)

  ;; Full demo
  (run-full-demo)

  (println "\n=== All Tests Complete ==="))
```

---

## Summary

In this lab you learned:
- Building multi-stage processing pipelines
- Sharing state between pipeline stages
- Implementing various processing stages (parser, validator, classifier, etc.)
- Routing packets based on classification
- Monitoring pipeline statistics and performance

## Next Steps

- Try Lab 18.3 to learn about hot updates
- Add custom stages for your specific use case
- Implement parallel stage execution
