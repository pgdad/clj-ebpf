;; Lab 18.2 Solution: Pipeline Architecture
;; Implement a multi-stage processing pipeline with shared state
;;
;; Learning Goals:
;; - Build multi-stage processing pipelines
;; - Share state between pipeline stages
;; - Implement various processing stages
;; - Monitor pipeline statistics and performance

(ns lab-18-2-pipeline-architecture
  (:require [clojure.string :as str])
  (:import [java.util UUID]
           [java.time Instant]
           [java.util.concurrent.atomic AtomicLong]))

;; ============================================================================
;; Pipeline Stage Interface
;; ============================================================================

(defprotocol IPipelineStage
  "Interface for pipeline stages"
  (process [this ctx])
  (stage-name [this])
  (stage-id [this]))

;; ============================================================================
;; Pipeline Context
;; ============================================================================

(defrecord PipelineContext [packet state metadata])

(defn create-context
  "Create a new pipeline context for a packet"
  [packet]
  (->PipelineContext
    packet
    (atom {})
    (atom {:created-at (Instant/now)
           :stage-times {}})))

(defn get-state
  "Get state value from context"
  [ctx key]
  (get @(:state ctx) key))

(defn set-state!
  "Set state value in context"
  [ctx key value]
  (swap! (:state ctx) assoc key value))

(defn update-state!
  "Update state value in context"
  [ctx key f & args]
  (apply swap! (:state ctx) update key f args))

(defn add-metadata!
  "Add metadata to context"
  [ctx key value]
  (swap! (:metadata ctx) assoc key value))

(defn record-stage-time!
  "Record execution time for a stage"
  [ctx stage-name time-ns]
  (swap! (:metadata ctx) update-in [:stage-times stage-name]
         (fnil conj []) time-ns))

;; ============================================================================
;; Pipeline Manager
;; ============================================================================

(defrecord Pipeline [stages shared-state stats])

(defn create-pipeline
  "Create a new pipeline"
  []
  (->Pipeline
    (atom [])
    (atom {})
    (atom {:processed (AtomicLong. 0)
           :passed (AtomicLong. 0)
           :dropped (AtomicLong. 0)
           :errors (AtomicLong. 0)
           :stage-times (atom {})})))

(defn add-stage!
  "Add a stage to the pipeline"
  [pipeline stage]
  (swap! (:stages pipeline) conj stage)
  (println (format "Added stage: %s (ID: %s)"
                   (stage-name stage)
                   (subs (stage-id stage) 0 8))))

(defn remove-stage!
  "Remove a stage from the pipeline by ID"
  [pipeline target-stage-id]
  (swap! (:stages pipeline)
         (fn [stages]
           (vec (remove #(= target-stage-id (stage-id %)) stages)))))

(defn get-stages
  "Get all stages in the pipeline"
  [pipeline]
  @(:stages pipeline))

(defn get-shared-state
  "Get shared state across pipeline"
  [pipeline key]
  (get @(:shared-state pipeline) key))

(defn set-shared-state!
  "Set shared state across pipeline"
  [pipeline key value]
  (swap! (:shared-state pipeline) assoc key value))

;; ============================================================================
;; Parser Stage
;; ============================================================================

(defrecord ParserStage [id config]
  IPipelineStage
  (process [this ctx]
    (let [packet (:packet ctx)]
      ;; Parse packet headers into structured data
      (set-state! ctx :parsed
                  {:protocol (:protocol packet)
                   :src-ip (:src-ip packet)
                   :dst-ip (:dst-ip packet)
                   :src-port (:src-port packet)
                   :dst-port (:dst-port packet)
                   :size (:payload-size packet)
                   :timestamp (System/currentTimeMillis)})
      {:action :continue
       :stage id}))

  (stage-name [_] "Parser")
  (stage-id [_] id))

(defn create-parser-stage
  "Create a parser stage"
  [config]
  (->ParserStage (str (UUID/randomUUID)) config))

;; ============================================================================
;; Validator Stage
;; ============================================================================

(def default-validation-rules
  {:min-packet-size 20
   :max-packet-size 9000
   :blocked-ports #{23 135 139 445}
   :blocked-protocols #{}
   :blocked-ips #{}})

(defrecord ValidatorStage [id config]
  IPipelineStage
  (process [this ctx]
    (let [parsed (get-state ctx :parsed)
          rules (merge default-validation-rules (:rules config))
          size (:size parsed)
          dst-port (:dst-port parsed)
          protocol (:protocol parsed)
          src-ip (:src-ip parsed)]

      (cond
        ;; Check packet size
        (< size (:min-packet-size rules))
        (do
          (set-state! ctx :drop-reason :packet-too-small)
          {:action :drop :stage id :reason :packet-too-small})

        (> size (:max-packet-size rules))
        (do
          (set-state! ctx :drop-reason :packet-too-large)
          {:action :drop :stage id :reason :packet-too-large})

        ;; Check blocked ports
        (contains? (:blocked-ports rules) dst-port)
        (do
          (set-state! ctx :drop-reason :blocked-port)
          {:action :drop :stage id :reason :blocked-port :port dst-port})

        ;; Check blocked protocols
        (contains? (:blocked-protocols rules) protocol)
        (do
          (set-state! ctx :drop-reason :blocked-protocol)
          {:action :drop :stage id :reason :blocked-protocol})

        ;; Check blocked IPs
        (contains? (:blocked-ips rules) src-ip)
        (do
          (set-state! ctx :drop-reason :blocked-ip)
          {:action :drop :stage id :reason :blocked-ip :ip src-ip})

        :else
        (do
          (set-state! ctx :validated true)
          {:action :continue :stage id}))))

  (stage-name [_] "Validator")
  (stage-id [_] id))

(defn create-validator-stage
  "Create a validator stage"
  [config]
  (->ValidatorStage (str (UUID/randomUUID)) config))

;; ============================================================================
;; Classifier Stage
;; ============================================================================

(def traffic-classes
  {:web      #{80 443 8080 8443}
   :dns      #{53}
   :ssh      #{22}
   :mail     #{25 465 587 993 995}
   :database #{3306 5432 27017 6379}
   :voip     #{5060 5061}})

(def protocol-priorities
  {:dns      :critical
   :ssh      :high
   :voip     :high
   :web      :medium
   :database :medium
   :mail     :low})

(defrecord ClassifierStage [id config]
  IPipelineStage
  (process [this ctx]
    (let [parsed (get-state ctx :parsed)
          dst-port (:dst-port parsed)
          traffic-class (or (first (for [[class ports] traffic-classes
                                         :when (contains? ports dst-port)]
                                     class))
                            :other)
          priority (get protocol-priorities traffic-class :low)]

      (set-state! ctx :traffic-class traffic-class)
      (set-state! ctx :priority priority)

      {:action :continue
       :stage id
       :class traffic-class
       :priority priority}))

  (stage-name [_] "Classifier")
  (stage-id [_] id))

(defn create-classifier-stage
  "Create a classifier stage"
  [config]
  (->ClassifierStage (str (UUID/randomUUID)) config))

;; ============================================================================
;; Transformer Stage
;; ============================================================================

(defrecord TransformerStage [id config]
  IPipelineStage
  (process [this ctx]
    (let [parsed (get-state ctx :parsed)
          transforms (or (:transforms config)
                         {:add-timestamp true
                          :normalize-ips true
                          :compute-hash true})]

      ;; Add timestamp
      (when (:add-timestamp transforms)
        (set-state! ctx :timestamp (System/currentTimeMillis)))

      ;; Normalize IPs
      (when (:normalize-ips transforms)
        (set-state! ctx :normalized-src (str/lower-case (:src-ip parsed)))
        (set-state! ctx :normalized-dst (str/lower-case (:dst-ip parsed))))

      ;; Compute flow hash
      (when (:compute-hash transforms)
        (set-state! ctx :flow-hash
                    (hash [(:src-ip parsed)
                           (:dst-ip parsed)
                           (:src-port parsed)
                           (:dst-port parsed)])))

      ;; Add tags
      (when (:add-tags transforms)
        (set-state! ctx :tags
                    (cond-> #{}
                      (< (:size parsed) 100) (conj :small-packet)
                      (> (:size parsed) 1400) (conj :large-packet)
                      (= 6 (:protocol parsed)) (conj :tcp)
                      (= 17 (:protocol parsed)) (conj :udp))))

      {:action :continue :stage id}))

  (stage-name [_] "Transformer")
  (stage-id [_] id))

(defn create-transformer-stage
  "Create a transformer stage"
  [config]
  (->TransformerStage (str (UUID/randomUUID)) config))

;; ============================================================================
;; Rate Limiter Stage
;; ============================================================================

(defrecord RateLimiterStage [id config counters window-start]
  IPipelineStage
  (process [this ctx]
    (let [parsed (get-state ctx :parsed)
          src-ip (:src-ip parsed)
          limits (or (:limits config) {:per-ip 1000})
          now (System/currentTimeMillis)]

      ;; Reset counters every second
      (when (> (- now @window-start) 1000)
        (reset! window-start now)
        (reset! counters {}))

      ;; Check rate limit
      (let [current (get @counters src-ip 0)
            limit (:per-ip limits)]
        (if (>= current limit)
          (do
            (set-state! ctx :drop-reason :rate-limited)
            {:action :drop :stage id :reason :rate-limited :ip src-ip})
          (do
            (swap! counters update src-ip (fnil inc 0))
            {:action :continue :stage id})))))

  (stage-name [_] "RateLimiter")
  (stage-id [_] id))

(defn create-rate-limiter-stage
  "Create a rate limiter stage"
  [config]
  (->RateLimiterStage
    (str (UUID/randomUUID))
    config
    (atom {})
    (atom (System/currentTimeMillis))))

;; ============================================================================
;; Router Stage
;; ============================================================================

(def default-routing-rules
  [{:match {:traffic-class :web} :output :web-queue}
   {:match {:traffic-class :dns} :output :dns-queue}
   {:match {:traffic-class :ssh} :output :secure-queue}
   {:match {:priority :critical} :output :priority-queue}
   {:match {:priority :high} :output :priority-queue}
   {:match {} :output :default-queue}])

(defrecord RouterStage [id config]
  IPipelineStage
  (process [this ctx]
    (let [traffic-class (get-state ctx :traffic-class)
          priority (get-state ctx :priority)
          current-state {:traffic-class traffic-class :priority priority}
          rules (or (:rules config) default-routing-rules)
          matching-rule (first
                          (filter
                            (fn [rule]
                              (every? (fn [[k v]]
                                        (= v (get current-state k)))
                                      (:match rule)))
                            rules))
          output (or (:output matching-rule) :default-queue)]

      (set-state! ctx :output-queue output)
      {:action :route :stage id :output output}))

  (stage-name [_] "Router")
  (stage-id [_] id))

(defn create-router-stage
  "Create a router stage"
  [config]
  (->RouterStage (str (UUID/randomUUID)) config))

;; ============================================================================
;; Logger Stage
;; ============================================================================

(defrecord LoggerStage [id config log-fn]
  IPipelineStage
  (process [this ctx]
    (let [parsed (get-state ctx :parsed)
          traffic-class (get-state ctx :traffic-class)
          level (or (:level config) :debug)]
      (when log-fn
        (log-fn {:level level
                 :src (:src-ip parsed)
                 :dst (:dst-ip parsed)
                 :class traffic-class
                 :timestamp (System/currentTimeMillis)}))
      {:action :continue :stage id}))

  (stage-name [_] "Logger")
  (stage-id [_] id))

(defn create-logger-stage
  "Create a logger stage"
  [config log-fn]
  (->LoggerStage (str (UUID/randomUUID)) config log-fn))

;; ============================================================================
;; Pipeline Execution
;; ============================================================================

(defn run-pipeline
  "Execute all stages in the pipeline"
  [pipeline ctx]
  (let [stages (get-stages pipeline)
        stats (:stats pipeline)]

    (.incrementAndGet ^AtomicLong (:processed stats))

    (loop [remaining-stages stages
           last-result nil]
      (if (empty? remaining-stages)
        ;; All stages completed
        (do
          (.incrementAndGet ^AtomicLong (:passed stats))
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

          ;; Record stage timing
          (record-stage-time! ctx (stage-name stage) elapsed)

          ;; Update aggregate stats
          (swap! (get-in stats [:stage-times])
                 update (stage-name stage) (fnil conj []) elapsed)

          ;; Handle result
          (case (:action result)
            :continue
            (recur (rest remaining-stages) result)

            :drop
            (do
              (.incrementAndGet ^AtomicLong (:dropped stats))
              {:status :dropped
               :context ctx
               :result result})

            :route
            ;; Continue processing after routing decision
            (recur (rest remaining-stages) result)

            :error
            (do
              (.incrementAndGet ^AtomicLong (:errors stats))
              {:status :error
               :context ctx
               :result result})

            ;; Unknown action, continue
            (recur (rest remaining-stages) result)))))))

(defn process-packet
  "Process a single packet through the pipeline"
  [pipeline packet]
  (let [ctx (create-context packet)]
    (run-pipeline pipeline ctx)))

(defn process-batch
  "Process multiple packets through the pipeline"
  [pipeline packets]
  (let [results (atom {:completed [] :dropped [] :errors []})]
    (doseq [packet packets]
      (let [result (process-packet pipeline packet)]
        (case (:status result)
          :completed (swap! results update :completed conj result)
          :dropped (swap! results update :dropped conj result)
          :error (swap! results update :errors conj result)
          nil)))
    @results))

;; ============================================================================
;; Statistics
;; ============================================================================

(defn get-pipeline-stats
  "Get pipeline statistics"
  [pipeline]
  (let [stats (:stats pipeline)
        processed (.get ^AtomicLong (:processed stats))
        passed (.get ^AtomicLong (:passed stats))
        dropped (.get ^AtomicLong (:dropped stats))
        errors (.get ^AtomicLong (:errors stats))
        stage-times @(:stage-times stats)]
    {:processed processed
     :passed passed
     :dropped dropped
     :errors errors
     :pass-rate (if (pos? processed)
                  (* 100.0 (/ passed processed))
                  0.0)
     :drop-rate (if (pos? processed)
                  (* 100.0 (/ dropped processed))
                  0.0)
     :avg-stage-times (into {}
                        (for [[stage times] stage-times]
                          [stage (if (seq times)
                                   (/ (reduce + times) (count times) 1000.0)
                                   0.0)]))}))

(defn display-pipeline-stats
  "Display pipeline statistics"
  [pipeline]
  (let [stats (get-pipeline-stats pipeline)]
    (println "\n=== Pipeline Statistics ===\n")
    (println (format "Processed:  %d" (:processed stats)))
    (println (format "Passed:     %d (%.1f%%)" (:passed stats) (:pass-rate stats)))
    (println (format "Dropped:    %d (%.1f%%)" (:dropped stats) (:drop-rate stats)))
    (println (format "Errors:     %d" (:errors stats)))

    (when (seq (:avg-stage-times stats))
      (println "\nAverage Stage Times (microseconds):")
      (doseq [[stage avg-time] (sort-by val (:avg-stage-times stats))]
        (println (format "  %-15s %.2f us" stage avg-time))))))

;; ============================================================================
;; Output Queue Statistics
;; ============================================================================

(def output-queues (atom {}))

(defn record-output
  "Record packet output to queue"
  [output-queue ctx]
  (swap! output-queues update output-queue
         (fn [q]
           (-> (or q {:count 0 :bytes 0})
               (update :count inc)
               (update :bytes + (get-in @(:state ctx) [:parsed :size] 0))))))

(defn display-queue-stats
  "Display output queue statistics"
  []
  (println "\n=== Output Queue Statistics ===\n")
  (println (format "%-20s %10s %15s" "Queue" "Packets" "Bytes"))
  (println (apply str (repeat 48 "-")))
  (doseq [[queue stats] (sort-by key @output-queues)]
    (println (format "%-20s %10d %15d"
                     (name queue)
                     (:count stats)
                     (:bytes stats)))))

;; ============================================================================
;; Packet Generation
;; ============================================================================

(defn generate-test-packets
  "Generate test packets"
  [n]
  (for [_ (range n)]
    {:protocol (rand-nth [6 17 1])
     :src-ip (str (rand-int 256) "." (rand-int 256) "."
                  (rand-int 256) "." (rand-int 256))
     :dst-ip (str (rand-int 256) "." (rand-int 256) "."
                  (rand-int 256) "." (rand-int 256))
     :src-port (+ 1024 (rand-int 64000))
     :dst-port (rand-nth [80 443 53 22 25 3306 8080 12345 23])
     :payload-size (+ 64 (rand-int 1400))}))

;; ============================================================================
;; Exercises
;; ============================================================================

(defn exercise-deduplication []
  "Exercise 2: Implement packet deduplication"
  (println "\n=== Exercise: Deduplication Stage ===\n")

  (let [seen-hashes (atom #{})
        window-start (atom (System/currentTimeMillis))
        duplicates (atom 0)

        dedup-stage
        (reify IPipelineStage
          (process [_ ctx]
            (let [parsed (get-state ctx :parsed)
                  now (System/currentTimeMillis)
                  packet-hash (hash [(:src-ip parsed)
                                     (:dst-ip parsed)
                                     (:src-port parsed)
                                     (:dst-port parsed)
                                     (:size parsed)])]
              ;; Clear cache every 5 seconds
              (when (> (- now @window-start) 5000)
                (reset! window-start now)
                (reset! seen-hashes #{}))

              (if (contains? @seen-hashes packet-hash)
                (do
                  (swap! duplicates inc)
                  (set-state! ctx :drop-reason :duplicate)
                  {:action :drop :reason :duplicate})
                (do
                  (swap! seen-hashes conj packet-hash)
                  {:action :continue}))))
          (stage-name [_] "Deduplicator")
          (stage-id [_] "dedup-stage"))

        pipeline (create-pipeline)]

    (add-stage! pipeline (create-parser-stage {}))
    (add-stage! pipeline dedup-stage)
    (add-stage! pipeline (create-classifier-stage {}))

    ;; Generate packets with some duplicates
    (let [base-packets (generate-test-packets 50)
          ;; Add some duplicates
          all-packets (concat base-packets (take 20 base-packets))]

      (println (format "Processing %d packets (with duplicates)..." (count all-packets)))
      (process-batch pipeline all-packets)

      (display-pipeline-stats pipeline)
      (println (format "\nDuplicates detected: %d" @duplicates)))))

(defn exercise-dynamic-config []
  "Exercise 3: Dynamic stage configuration"
  (println "\n=== Exercise: Dynamic Configuration ===\n")

  (let [config (atom {:blocked-ports #{23}})
        config-version (atom 0)

        update-config!
        (fn [new-config]
          (swap! config merge new-config)
          (swap! config-version inc)
          (println (format "Config updated to version %d: %s"
                           @config-version @config)))

        dynamic-validator
        (reify IPipelineStage
          (process [_ ctx]
            (let [parsed (get-state ctx :parsed)
                  current-config @config]
              (if (contains? (:blocked-ports current-config)
                             (:dst-port parsed))
                {:action :drop :reason :blocked-port}
                {:action :continue})))
          (stage-name [_] "DynamicValidator")
          (stage-id [_] "dynamic-validator"))

        pipeline (create-pipeline)]

    (add-stage! pipeline (create-parser-stage {}))
    (add-stage! pipeline dynamic-validator)

    ;; Test with initial config
    (println "Initial config - blocking port 23:")
    (let [packets (generate-test-packets 100)]
      (process-batch pipeline packets)
      (display-pipeline-stats pipeline))

    ;; Update config
    (update-config! {:blocked-ports #{23 80 443}})

    ;; Reset stats
    (reset! (:processed (:stats pipeline)) (AtomicLong. 0))
    (reset! (:dropped (:stats pipeline)) (AtomicLong. 0))
    (reset! (:passed (:stats pipeline)) (AtomicLong. 0))

    ;; Test with updated config
    (println "\nUpdated config - blocking ports 23, 80, 443:")
    (let [packets (generate-test-packets 100)]
      (process-batch pipeline packets)
      (display-pipeline-stats pipeline))))

;; ============================================================================
;; Test Functions
;; ============================================================================

(defn test-pipeline-creation []
  (println "Testing pipeline creation...")

  (let [pipeline (create-pipeline)]
    (assert (empty? (get-stages pipeline)) "Should start empty")

    (add-stage! pipeline (create-parser-stage {}))
    (assert (= 1 (count (get-stages pipeline))) "Should have 1 stage")

    (add-stage! pipeline (create-validator-stage {}))
    (assert (= 2 (count (get-stages pipeline))) "Should have 2 stages"))

  (println "Pipeline creation tests passed!"))

(defn test-stage-processing []
  (println "Testing stage processing...")

  (let [parser (create-parser-stage {})
        packet {:protocol 6 :src-ip "1.2.3.4" :dst-ip "5.6.7.8"
                :src-port 12345 :dst-port 80 :payload-size 100}
        ctx (create-context packet)]

    (let [result (process parser ctx)]
      (assert (= :continue (:action result)) "Parser should continue")
      (assert (some? (get-state ctx :parsed)) "Should have parsed state")))

  (println "Stage processing tests passed!"))

(defn test-full-pipeline []
  (println "Testing full pipeline...")

  (let [pipeline (create-pipeline)]
    (add-stage! pipeline (create-parser-stage {}))
    (add-stage! pipeline (create-validator-stage {:rules {:blocked-ports #{23}}}))
    (add-stage! pipeline (create-classifier-stage {}))
    (add-stage! pipeline (create-transformer-stage {}))
    (add-stage! pipeline (create-router-stage {}))

    ;; Valid packet to port 80
    (let [packet {:protocol 6 :src-ip "1.2.3.4" :dst-ip "5.6.7.8"
                  :src-port 12345 :dst-port 80 :payload-size 100}
          result (process-packet pipeline packet)]
      (assert (= :completed (:status result)) "Should complete")
      (assert (= :web-queue (get-state (:context result) :output-queue))
              "Should route to web queue"))

    ;; Blocked packet to port 23
    (let [packet {:protocol 6 :src-ip "1.2.3.4" :dst-ip "5.6.7.8"
                  :src-port 12345 :dst-port 23 :payload-size 100}
          result (process-packet pipeline packet)]
      (assert (= :dropped (:status result)) "Should drop blocked port")))

  (println "Full pipeline tests passed!"))

(defn run-demo []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "         Pipeline Architecture Demo")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  (reset! output-queues {})

  (let [pipeline (create-pipeline)]
    ;; Build pipeline
    (add-stage! pipeline (create-parser-stage {}))
    (add-stage! pipeline (create-validator-stage {:rules {:blocked-ports #{23}}}))
    (add-stage! pipeline (create-rate-limiter-stage {:limits {:per-ip 100}}))
    (add-stage! pipeline (create-classifier-stage {}))
    (add-stage! pipeline (create-transformer-stage
                           {:transforms {:add-timestamp true
                                         :normalize-ips true
                                         :compute-hash true
                                         :add-tags true}}))
    (add-stage! pipeline (create-router-stage {}))

    (println "\nProcessing 1000 packets...\n")
    (let [packets (generate-test-packets 1000)]
      (doseq [packet packets]
        (let [result (process-packet pipeline packet)]
          (when (= :completed (:status result))
            (let [ctx (:context result)
                  output (get-state ctx :output-queue)]
              (record-output output ctx))))))

    (display-pipeline-stats pipeline)
    (display-queue-stats)))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the pipeline architecture lab"
  [& args]
  (println "Lab 18.2: Pipeline Architecture")
  (println "================================\n")

  (let [command (first args)]
    (case command
      "test"
      (do
        (test-pipeline-creation)
        (test-stage-processing)
        (test-full-pipeline)
        (println "\nAll tests passed!"))

      "demo"
      (run-demo)

      "exercise2"
      (exercise-deduplication)

      "exercise3"
      (exercise-dynamic-config)

      ;; Default: run all
      (do
        (test-pipeline-creation)
        (test-stage-processing)
        (test-full-pipeline)
        (run-demo)
        (exercise-deduplication)
        (exercise-dynamic-config)

        (println "\n=== Key Takeaways ===")
        (println "1. Pipelines enable modular packet processing")
        (println "2. Stages share state through context objects")
        (println "3. Each stage can pass, drop, or route packets")
        (println "4. Statistics help monitor pipeline performance")
        (println "5. Configuration can be updated at runtime")))))

;; Run with: clj -M -m lab-18-2-pipeline-architecture
