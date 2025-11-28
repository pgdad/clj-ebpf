# Lab 17.2: Data Sanitization Pipeline

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Objective

Build a comprehensive data sanitization pipeline that protects sensitive information in BPF events before logging, storage, or transmission.

## Prerequisites

- Completed Lab 17.1
- Understanding of data privacy requirements
- Familiarity with regex patterns

## Scenario

Your BPF monitoring system captures network packets and process events that may contain sensitive data like passwords, API keys, and PII. You need to sanitize this data while maintaining its usefulness for debugging and analysis.

---

## Part 1: Sensitive Data Detection

### Step 1.1: Pattern Definitions

```clojure
(ns lab-17-2.data-sanitization
  (:require [clojure.string :as str]
            [clojure.walk :as walk])
  (:import [java.security MessageDigest]
           [java.util Base64]))

;; Patterns for sensitive data
(def sensitive-patterns
  {:password       #"(?i)(password|passwd|pwd)[=:\"'\s]+\S+"
   :api-key        #"(?i)(api[_-]?key|apikey)[=:\"'\s]+[\w-]+"
   :token          #"(?i)(token|bearer|auth)[=:\"'\s]+[\w.-]+"
   :credit-card    #"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"
   :ssn            #"\b\d{3}-\d{2}-\d{4}\b"
   :email          #"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
   :ip-address     #"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
   :phone          #"\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"
   :private-key    #"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----"
   :jwt            #"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"})

(defn detect-sensitive-data [text]
  "Detect all sensitive data types in text"
  (for [[type pattern] sensitive-patterns
        :let [matches (re-seq pattern text)]
        :when (seq matches)]
    {:type type
     :matches matches
     :count (count matches)}))

(defn contains-sensitive-data? [text]
  "Quick check if text contains any sensitive data"
  (some (fn [[_ pattern]]
          (re-find pattern text))
        sensitive-patterns))
```

### Step 1.2: Field-Level Detection

```clojure
(def sensitive-field-names
  "Field names that typically contain sensitive data"
  #{:password :passwd :pwd :secret :token :api-key :apiKey :api_key
    :authorization :auth :credential :credentials :private-key
    :privateKey :private_key :ssn :social-security :credit-card
    :creditCard :credit_card :cvv :pin})

(defn is-sensitive-field? [field-name]
  "Check if a field name suggests sensitive content"
  (let [normalized (-> field-name name str/lower-case keyword)]
    (or (contains? sensitive-field-names normalized)
        (some #(str/includes? (name field-name) (name %))
              sensitive-field-names))))

(defn scan-event-for-sensitive-fields [event]
  "Scan an event map for sensitive field names"
  (let [sensitive-fields (atom [])]
    (walk/prewalk
      (fn [x]
        (when (map-entry? x)
          (let [[k _] x]
            (when (is-sensitive-field? k)
              (swap! sensitive-fields conj k))))
        x)
      event)
    @sensitive-fields))
```

---

## Part 2: Sanitization Strategies

### Step 2.1: Redaction

```clojure
(defn redact-value [value]
  "[REDACTED]")

(defn partial-redact [value visible-chars]
  "Keep first N characters visible, redact rest"
  (if (string? value)
    (let [len (count value)]
      (if (<= len visible-chars)
        "[REDACTED]"
        (str (subs value 0 visible-chars) "***REDACTED***")))
    "[REDACTED]"))

(defn redact-patterns [text patterns]
  "Redact all matches of patterns in text"
  (reduce
    (fn [t [type pattern]]
      (str/replace t pattern (str "[REDACTED:" (name type) "]")))
    text
    patterns))

(defn redact-all-sensitive [text]
  "Redact all known sensitive patterns"
  (redact-patterns text sensitive-patterns))
```

### Step 2.2: Masking

```clojure
(defn mask-credit-card [card-number]
  "Show only last 4 digits: ****-****-****-1234"
  (let [clean (str/replace card-number #"[- ]" "")]
    (if (= 16 (count clean))
      (str "****-****-****-" (subs clean 12))
      "[INVALID-CARD]")))

(defn mask-email [email]
  "Show domain only: ***@example.com"
  (if-let [[_ _ domain] (re-matches #"([^@]+)@(.+)" email)]
    (str "***@" domain)
    "[INVALID-EMAIL]"))

(defn mask-ip-address [ip]
  "Mask last octet: 192.168.1.xxx"
  (if-let [[_ a b c _] (re-matches #"(\d+)\.(\d+)\.(\d+)\.(\d+)" ip)]
    (str a "." b "." c ".xxx")
    "[INVALID-IP]"))

(defn mask-phone [phone]
  "Show only last 4 digits: (***) ***-1234"
  (let [digits (str/replace phone #"[^0-9]" "")]
    (if (>= (count digits) 4)
      (str "(***) ***-" (subs digits (- (count digits) 4)))
      "[INVALID-PHONE]")))

(def masking-functions
  {:credit-card mask-credit-card
   :email mask-email
   :ip-address mask-ip-address
   :phone mask-phone})

(defn apply-masking [text data-type]
  "Apply appropriate masking for data type"
  (if-let [mask-fn (get masking-functions data-type)]
    (mask-fn text)
    (redact-value text)))
```

### Step 2.3: Hashing/Pseudonymization

```clojure
(defn sha256-hash [text]
  "Create SHA-256 hash of text"
  (let [digest (MessageDigest/getInstance "SHA-256")
        hash-bytes (.digest digest (.getBytes text "UTF-8"))]
    (->> hash-bytes
         (map #(format "%02x" %))
         (apply str))))

(defn pseudonymize [value salt]
  "Create consistent pseudonym for value"
  (let [salted (str salt ":" value)
        hash (sha256-hash salted)]
    (str "PSEUDO:" (subs hash 0 16))))

(defn tokenize [value token-map]
  "Replace value with consistent token"
  (if-let [token (get @token-map value)]
    token
    (let [new-token (str "TOKEN:" (count @token-map))]
      (swap! token-map assoc value new-token)
      new-token)))
```

---

## Part 3: Sanitization Pipeline

### Step 3.1: Pipeline Configuration

```clojure
(def default-sanitization-config
  {:strategies
   {:password :redact
    :api-key :redact
    :token :redact
    :credit-card :mask
    :ssn :redact
    :email :mask
    :ip-address :mask
    :phone :mask
    :private-key :redact
    :jwt :redact}

   :field-rules
   {:password :redact
    :secret :redact
    :token :redact
    :api-key :redact}

   :enable-content-scan true
   :enable-field-scan true
   :pseudonymization-salt "default-salt"})

(defn create-sanitization-pipeline [config]
  {:config (merge default-sanitization-config config)
   :token-map (atom {})
   :stats (atom {:events-processed 0
                 :fields-sanitized 0
                 :patterns-matched 0})})
```

### Step 3.2: Field Sanitizer

```clojure
(defn sanitize-field-value [pipeline field-name value]
  (let [config (:config pipeline)
        strategy (get-in config [:field-rules (keyword field-name)])]
    (case strategy
      :redact (do
                (swap! (:stats pipeline) update :fields-sanitized inc)
                "[REDACTED]")
      :mask (partial-redact value 3)
      :hash (sha256-hash value)
      :pseudonymize (pseudonymize value (:pseudonymization-salt config))
      :tokenize (tokenize value (:token-map pipeline))
      ;; Default: return as-is
      value)))

(defn sanitize-map-fields [pipeline m]
  "Sanitize sensitive fields in a map"
  (walk/postwalk
    (fn [x]
      (if (map-entry? x)
        (let [[k v] x]
          (if (is-sensitive-field? k)
            [k (sanitize-field-value pipeline k v)]
            x))
        x))
    m))
```

### Step 3.3: Content Sanitizer

```clojure
(defn sanitize-content [pipeline text]
  "Sanitize sensitive patterns in text content"
  (let [config (:config pipeline)]
    (reduce
      (fn [t [data-type pattern]]
        (let [strategy (get-in config [:strategies data-type] :redact)]
          (if (re-find pattern t)
            (do
              (swap! (:stats pipeline) update :patterns-matched inc)
              (case strategy
                :redact (str/replace t pattern
                                     (str "[REDACTED:" (name data-type) "]"))
                :mask (str/replace t pattern
                                   #(apply-masking % data-type))
                t))
            t)))
      text
      sensitive-patterns)))

(defn sanitize-value [pipeline value]
  "Sanitize a single value (string or other)"
  (if (string? value)
    (sanitize-content pipeline value)
    value))
```

### Step 3.4: Complete Event Sanitizer

```clojure
(defn sanitize-event [pipeline event]
  "Fully sanitize an event through the pipeline"
  (swap! (:stats pipeline) update :events-processed inc)

  (let [config (:config pipeline)
        step1 (if (:enable-field-scan config)
                (sanitize-map-fields pipeline event)
                event)
        step2 (if (:enable-content-scan config)
                (walk/postwalk
                  (fn [x]
                    (if (string? x)
                      (sanitize-value pipeline x)
                      x))
                  step1)
                step1)]
    step2))

(defn sanitize-events [pipeline events]
  "Sanitize a batch of events"
  (map #(sanitize-event pipeline %) events))
```

---

## Part 4: Specialized Sanitizers

### Step 4.1: Network Packet Sanitizer

```clojure
(defn sanitize-http-headers [headers]
  "Sanitize sensitive HTTP headers"
  (let [sensitive-headers #{"authorization" "cookie" "set-cookie"
                            "x-api-key" "x-auth-token"}]
    (into {}
      (for [[k v] headers]
        (if (contains? sensitive-headers (str/lower-case k))
          [k "[REDACTED]"]
          [k v])))))

(defn sanitize-packet-payload [payload]
  "Sanitize HTTP-like payload content"
  (-> payload
      ;; Redact Authorization headers
      (str/replace #"(?i)Authorization:\s*\S+" "Authorization: [REDACTED]")
      ;; Redact cookies
      (str/replace #"(?i)Cookie:\s*[^\r\n]+" "Cookie: [REDACTED]")
      ;; Redact form passwords
      (str/replace #"(?i)(password|passwd)=[^&\s]+" "$1=[REDACTED]")
      ;; Redact JSON passwords
      (str/replace #"(?i)\"(password|passwd|secret)\"\s*:\s*\"[^\"]*\""
                   "\"$1\": \"[REDACTED]\"")))

(defn sanitize-network-event [pipeline event]
  (-> event
      (update :payload sanitize-packet-payload)
      (update :headers sanitize-http-headers)
      (update :src-ip mask-ip-address)
      (update :dst-ip mask-ip-address)))
```

### Step 4.2: Process Event Sanitizer

```clojure
(defn sanitize-command-line [cmdline]
  "Sanitize sensitive data in command line arguments"
  (-> cmdline
      ;; Password arguments
      (str/replace #"(?i)(-p|--password)[=\s]+\S+" "$1=[REDACTED]")
      ;; Token arguments
      (str/replace #"(?i)(-t|--token)[=\s]+\S+" "$1=[REDACTED]")
      ;; API key arguments
      (str/replace #"(?i)(--api-key|--apikey)[=\s]+\S+" "$1=[REDACTED]")
      ;; Environment variable assignments
      (str/replace #"(?i)(PASSWORD|SECRET|TOKEN|API_KEY)=\S+"
                   "$1=[REDACTED]")))

(defn sanitize-environment [env-vars]
  "Sanitize sensitive environment variables"
  (let [sensitive-vars #{"PASSWORD" "SECRET" "TOKEN" "API_KEY" "AWS_SECRET"
                        "DATABASE_PASSWORD" "DB_PASSWORD" "PRIVATE_KEY"}]
    (into {}
      (for [[k v] env-vars]
        (if (some #(str/includes? (str/upper-case k) %) sensitive-vars)
          [k "[REDACTED]"]
          [k v])))))

(defn sanitize-process-event [pipeline event]
  (-> event
      (update :cmdline sanitize-command-line)
      (update :env sanitize-environment)))
```

---

## Part 5: Pipeline Integration

### Step 5.1: Stream Processing

```clojure
(defn create-sanitizing-stream [pipeline input-chan output-chan]
  "Create a sanitizing stream processor"
  (future
    (loop []
      (when-let [event (async/<!! input-chan)]
        (let [sanitized (sanitize-event pipeline event)]
          (async/>!! output-chan sanitized))
        (recur)))))

(defn process-event-stream [pipeline events]
  "Process a stream of events with sanitization"
  (let [results (atom [])]
    (doseq [event events]
      (let [sanitized (sanitize-event pipeline event)]
        (swap! results conj sanitized)))
    @results))
```

### Step 5.2: Pipeline Statistics

```clojure
(defn get-pipeline-stats [pipeline]
  @(:stats pipeline))

(defn display-pipeline-stats [pipeline]
  (let [stats (get-pipeline-stats pipeline)]
    (println "\n=== Sanitization Pipeline Statistics ===")
    (println (format "Events processed:  %d" (:events-processed stats)))
    (println (format "Fields sanitized:  %d" (:fields-sanitized stats)))
    (println (format "Patterns matched:  %d" (:patterns-matched stats)))))

(defn reset-pipeline-stats [pipeline]
  (reset! (:stats pipeline)
          {:events-processed 0
           :fields-sanitized 0
           :patterns-matched 0}))
```

---

## Part 6: Exercises

### Exercise 1: Custom Sanitization Rules

Add support for custom sanitization rules:

```clojure
(defn exercise-custom-rules []
  ;; TODO: Implement custom rule support
  ;; 1. Define custom regex patterns
  ;; 2. Define custom field names
  ;; 3. Define custom sanitization functions
  ;; 4. Integrate with pipeline
  )
```

### Exercise 2: Reversible Tokenization

Implement reversible tokenization with secure storage:

```clojure
(defn exercise-reversible-tokenization []
  ;; TODO: Implement reversible tokenization
  ;; 1. Encrypt original values before storing
  ;; 2. Generate unique tokens
  ;; 3. Store mapping securely
  ;; 4. Implement detokenization with authentication
  )
```

### Exercise 3: Audit Trail

Add audit logging for sanitization operations:

```clojure
(defn exercise-audit-trail []
  ;; TODO: Implement audit trail
  ;; 1. Log what was sanitized (without values)
  ;; 2. Track which rules matched
  ;; 3. Record timestamps
  ;; 4. Generate compliance reports
  )
```

---

## Part 7: Testing Your Implementation

### Test Script

```clojure
(defn test-pattern-detection []
  (println "Testing pattern detection...")

  ;; Test password detection
  (assert (contains-sensitive-data? "password=secret123")
          "Should detect password")
  (assert (contains-sensitive-data? "api_key: abc123xyz")
          "Should detect API key")
  (assert (contains-sensitive-data? "1234-5678-9012-3456")
          "Should detect credit card")
  (assert (not (contains-sensitive-data? "Hello World"))
          "Should not detect in clean text")

  (println "Pattern detection tests passed!"))

(defn test-sanitization []
  (println "Testing sanitization...")

  (let [pipeline (create-sanitization-pipeline {})]
    ;; Test field sanitization
    (let [event {:username "john"
                 :password "secret123"
                 :data "test"}
          result (sanitize-event pipeline event)]
      (assert (= "[REDACTED]" (:password result))
              "Password should be redacted")
      (assert (= "john" (:username result))
              "Username should not be changed"))

    ;; Test content sanitization
    (let [event {:message "Login with password=secret123"}
          result (sanitize-event pipeline event)]
      (assert (str/includes? (:message result) "REDACTED")
              "Password in content should be redacted"))

    ;; Test masking
    (assert (= "****-****-****-3456" (mask-credit-card "1234-5678-9012-3456"))
            "Credit card should be masked")
    (assert (= "***@example.com" (mask-email "user@example.com"))
            "Email should be masked")

    (println "Sanitization tests passed!")))

(defn test-specialized-sanitizers []
  (println "Testing specialized sanitizers...")

  ;; Test command line sanitization
  (let [cmdline "curl -u user:secret --password mypass http://example.com"
        result (sanitize-command-line cmdline)]
    (assert (str/includes? result "REDACTED")
            "Command line passwords should be redacted")
    (assert (not (str/includes? result "secret"))
            "Should not contain 'secret'")
    (assert (not (str/includes? result "mypass"))
            "Should not contain 'mypass'"))

  (println "Specialized sanitizer tests passed!"))

(defn run-all-tests []
  (println "\nLab 17.2: Data Sanitization Pipeline")
  (println "=====================================\n")

  (test-pattern-detection)
  (test-sanitization)
  (test-specialized-sanitizers)

  ;; Demo
  (println "\n=== Demo: Sanitizing Sample Events ===\n")
  (let [pipeline (create-sanitization-pipeline {})
        events [{:type :login
                 :username "alice"
                 :password "supersecret"
                 :ip "192.168.1.100"}
                {:type :api-call
                 :api-key "sk_live_abc123xyz"
                 :endpoint "/users"}
                {:type :payment
                 :card "4111-1111-1111-1234"
                 :amount 99.99}
                {:type :message
                 :content "Contact me at user@example.com or 555-123-4567"}]]

    (println "Original events:")
    (doseq [event events]
      (println " " event))

    (let [sanitized (sanitize-events pipeline events)]
      (println "\nSanitized events:")
      (doseq [event sanitized]
        (println " " event)))

    (display-pipeline-stats pipeline))

  (println "\n=== All Tests Complete ==="))
```

---

## Summary

In this lab you learned:
- Detecting sensitive data with regex patterns
- Multiple sanitization strategies (redact, mask, hash, tokenize)
- Building a configurable sanitization pipeline
- Specialized sanitizers for network and process events
- Integrating sanitization into event processing streams

## Next Steps

- Try Lab 17.3 to learn about security auditing
- Implement sanitization in your BPF event processors
- Create custom rules for your domain-specific sensitive data
