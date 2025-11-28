;; Lab 17.2 Solution: Data Sanitization Pipeline
;; Build a comprehensive data sanitization pipeline for BPF events
;;
;; Learning Goals:
;; - Detect sensitive data with regex patterns
;; - Apply multiple sanitization strategies
;; - Build a configurable sanitization pipeline
;; - Create specialized sanitizers for network and process events

(ns lab-17-2-data-sanitization
  (:require [clojure.string :as str]
            [clojure.walk :as walk])
  (:import [java.security MessageDigest]
           [java.util Base64]))

;; ============================================================================
;; Sensitive Data Patterns
;; ============================================================================

(def sensitive-patterns
  "Regex patterns for detecting sensitive data"
  {:password    #"(?i)(password|passwd|pwd)[=:\"'\s]+\S+"
   :api-key     #"(?i)(api[_-]?key|apikey)[=:\"'\s]+[\w-]+"
   :token       #"(?i)(token|bearer|auth)[=:\"'\s]+[\w.-]+"
   :credit-card #"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"
   :ssn         #"\b\d{3}-\d{2}-\d{4}\b"
   :email       #"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
   :ip-address  #"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
   :phone       #"\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"
   :private-key #"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----"
   :jwt         #"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
   :aws-key     #"(?i)(aws[_-]?access[_-]?key[_-]?id)[=:\"'\s]+[A-Z0-9]{20}"
   :aws-secret  #"(?i)(aws[_-]?secret[_-]?access[_-]?key)[=:\"'\s]+[A-Za-z0-9/+=]{40}"})

(defn detect-sensitive-data
  "Detect all sensitive data types in text"
  [text]
  (when (string? text)
    (for [[data-type pattern] sensitive-patterns
          :let [matches (re-seq pattern text)]
          :when (seq matches)]
      {:type data-type
       :matches matches
       :count (count matches)})))

(defn contains-sensitive-data?
  "Quick check if text contains any sensitive data"
  [text]
  (when (string? text)
    (some (fn [[_ pattern]]
            (re-find pattern text))
          sensitive-patterns)))

;; ============================================================================
;; Sensitive Field Detection
;; ============================================================================

(def sensitive-field-names
  "Field names that typically contain sensitive data"
  #{:password :passwd :pwd :secret :token :api-key :apiKey :api_key
    :authorization :auth :credential :credentials :private-key
    :privateKey :private_key :ssn :social-security :credit-card
    :creditCard :credit_card :cvv :pin :access-token :accessToken
    :refresh-token :refreshToken :session-id :sessionId :cookie
    :x-api-key :bearer :aws-secret :database-password :db-password})

(defn is-sensitive-field?
  "Check if a field name suggests sensitive content"
  [field-name]
  (when field-name
    (let [normalized (-> field-name name str/lower-case keyword)]
      (or (contains? sensitive-field-names normalized)
          (some #(str/includes? (name field-name) (name %))
                [:password :secret :token :key :auth :credential])))))

(defn scan-event-for-sensitive-fields
  "Scan an event map for sensitive field names"
  [event]
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

;; ============================================================================
;; Sanitization Strategies - Redaction
;; ============================================================================

(defn redact-value
  "Completely redact a value"
  [_value]
  "[REDACTED]")

(defn partial-redact
  "Keep first N characters visible, redact rest"
  [value visible-chars]
  (if (string? value)
    (let [len (count value)]
      (if (<= len visible-chars)
        "[REDACTED]"
        (str (subs value 0 visible-chars) "***REDACTED***")))
    "[REDACTED]"))

(defn redact-patterns
  "Redact all matches of patterns in text"
  [text patterns]
  (reduce
    (fn [t [data-type pattern]]
      (str/replace t pattern (str "[REDACTED:" (name data-type) "]")))
    text
    patterns))

(defn redact-all-sensitive
  "Redact all known sensitive patterns in text"
  [text]
  (redact-patterns text sensitive-patterns))

;; ============================================================================
;; Sanitization Strategies - Masking
;; ============================================================================

(defn mask-credit-card
  "Show only last 4 digits: ****-****-****-1234"
  [card-number]
  (when card-number
    (let [clean (str/replace card-number #"[- ]" "")]
      (if (= 16 (count clean))
        (str "****-****-****-" (subs clean 12))
        "[INVALID-CARD]"))))

(defn mask-email
  "Show domain only: ***@example.com"
  [email]
  (when email
    (if-let [[_ _ domain] (re-matches #"([^@]+)@(.+)" email)]
      (str "***@" domain)
      "[INVALID-EMAIL]")))

(defn mask-ip-address
  "Mask last octet: 192.168.1.xxx"
  [ip]
  (when ip
    (if-let [[_ a b c _] (re-matches #"(\d+)\.(\d+)\.(\d+)\.(\d+)" ip)]
      (str a "." b "." c ".xxx")
      "[INVALID-IP]")))

(defn mask-phone
  "Show only last 4 digits: (***) ***-1234"
  [phone]
  (when phone
    (let [digits (str/replace phone #"[^0-9]" "")]
      (if (>= (count digits) 4)
        (str "(***) ***-" (subs digits (- (count digits) 4)))
        "[INVALID-PHONE]"))))

(defn mask-ssn
  "Show only last 4 digits: ***-**-1234"
  [ssn]
  (when ssn
    (let [digits (str/replace ssn #"[^0-9]" "")]
      (if (= 9 (count digits))
        (str "***-**-" (subs digits 5))
        "[INVALID-SSN]"))))

(def masking-functions
  "Map of data types to masking functions"
  {:credit-card mask-credit-card
   :email       mask-email
   :ip-address  mask-ip-address
   :phone       mask-phone
   :ssn         mask-ssn})

(defn apply-masking
  "Apply appropriate masking for data type"
  [value data-type]
  (if-let [mask-fn (get masking-functions data-type)]
    (mask-fn value)
    (redact-value value)))

;; ============================================================================
;; Sanitization Strategies - Hashing/Pseudonymization
;; ============================================================================

(defn sha256-hash
  "Create SHA-256 hash of text"
  [text]
  (when text
    (let [digest (MessageDigest/getInstance "SHA-256")
          hash-bytes (.digest digest (.getBytes (str text) "UTF-8"))]
      (->> hash-bytes
           (map #(format "%02x" (bit-and % 0xff)))
           (apply str)))))

(defn pseudonymize
  "Create consistent pseudonym for value using salt"
  [value salt]
  (let [salted (str salt ":" value)
        hash (sha256-hash salted)]
    (str "PSEUDO:" (subs hash 0 16))))

(defn create-tokenizer
  "Create a tokenization function with internal mapping"
  []
  (let [token-map (atom {})
        reverse-map (atom {})]
    {:tokenize
     (fn [value]
       (if-let [token (get @token-map value)]
         token
         (let [new-token (str "TOKEN:" (count @token-map))]
           (swap! token-map assoc value new-token)
           (swap! reverse-map assoc new-token value)
           new-token)))
     :detokenize
     (fn [token]
       (get @reverse-map token))
     :get-mapping
     (fn []
       @token-map)}))

;; ============================================================================
;; Sanitization Pipeline Configuration
;; ============================================================================

(def default-sanitization-config
  "Default sanitization configuration"
  {:strategies
   {:password    :redact
    :api-key     :redact
    :token       :redact
    :credit-card :mask
    :ssn         :mask
    :email       :mask
    :ip-address  :mask
    :phone       :mask
    :private-key :redact
    :jwt         :redact
    :aws-key     :redact
    :aws-secret  :redact}

   :field-rules
   {:password         :redact
    :passwd           :redact
    :pwd              :redact
    :secret           :redact
    :token            :redact
    :api-key          :redact
    :apiKey           :redact
    :api_key          :redact
    :authorization    :redact
    :auth             :redact
    :credential       :redact
    :credentials      :redact
    :private-key      :redact
    :privateKey       :redact
    :private_key      :redact
    :access-token     :redact
    :accessToken      :redact
    :refresh-token    :redact
    :refreshToken     :redact
    :session-id       :redact
    :sessionId        :redact
    :cookie           :redact
    :ssn              :mask
    :credit-card      :mask
    :creditCard       :mask
    :credit_card      :mask
    :cvv              :redact
    :pin              :redact}

   :enable-content-scan true
   :enable-field-scan true
   :pseudonymization-salt "default-salt-change-in-production"})

(defn create-sanitization-pipeline
  "Create a new sanitization pipeline with config"
  [config]
  (let [merged-config (merge-with merge default-sanitization-config config)]
    {:config merged-config
     :tokenizer (create-tokenizer)
     :stats (atom {:events-processed 0
                   :fields-sanitized 0
                   :patterns-matched 0
                   :bytes-processed 0})}))

;; ============================================================================
;; Field Sanitizer
;; ============================================================================

(defn sanitize-field-value
  "Sanitize a single field value based on field name"
  [pipeline field-name value]
  (let [config (:config pipeline)
        strategy (get-in config [:field-rules (keyword field-name)])]
    (case strategy
      :redact
      (do
        (swap! (:stats pipeline) update :fields-sanitized inc)
        "[REDACTED]")

      :mask
      (do
        (swap! (:stats pipeline) update :fields-sanitized inc)
        (partial-redact (str value) 3))

      :hash
      (do
        (swap! (:stats pipeline) update :fields-sanitized inc)
        (sha256-hash (str value)))

      :pseudonymize
      (do
        (swap! (:stats pipeline) update :fields-sanitized inc)
        (pseudonymize value (:pseudonymization-salt config)))

      :tokenize
      (do
        (swap! (:stats pipeline) update :fields-sanitized inc)
        ((get-in pipeline [:tokenizer :tokenize]) value))

      ;; Default: return as-is
      value)))

(defn sanitize-map-fields
  "Sanitize sensitive fields in a map"
  [pipeline m]
  (walk/postwalk
    (fn [x]
      (if (map-entry? x)
        (let [[k v] x]
          (if (is-sensitive-field? k)
            [k (sanitize-field-value pipeline k v)]
            x))
        x))
    m))

;; ============================================================================
;; Content Sanitizer
;; ============================================================================

(defn sanitize-text-content
  "Sanitize sensitive patterns in text content"
  [pipeline text]
  (let [config (:config pipeline)]
    (reduce
      (fn [t [data-type pattern]]
        (let [strategy (get-in config [:strategies data-type] :redact)]
          (if (re-find pattern t)
            (do
              (swap! (:stats pipeline) update :patterns-matched inc)
              (case strategy
                :redact
                (str/replace t pattern (str "[REDACTED:" (name data-type) "]"))

                :mask
                (str/replace t pattern
                             (fn [match]
                               (apply-masking match data-type)))

                :hash
                (str/replace t pattern
                             (fn [match]
                               (str "[HASH:" (subs (sha256-hash match) 0 12) "]")))

                ;; Default: redact
                (str/replace t pattern (str "[REDACTED:" (name data-type) "]"))))
            t)))
      text
      sensitive-patterns)))

(defn sanitize-value
  "Sanitize a single value (string or other)"
  [pipeline value]
  (if (string? value)
    (do
      (swap! (:stats pipeline) update :bytes-processed + (count value))
      (sanitize-text-content pipeline value))
    value))

;; ============================================================================
;; Complete Event Sanitizer
;; ============================================================================

(defn sanitize-event
  "Fully sanitize an event through the pipeline"
  [pipeline event]
  (swap! (:stats pipeline) update :events-processed inc)

  (let [config (:config pipeline)
        ;; Step 1: Field-based sanitization
        step1 (if (:enable-field-scan config)
                (sanitize-map-fields pipeline event)
                event)
        ;; Step 2: Content-based sanitization
        step2 (if (:enable-content-scan config)
                (walk/postwalk
                  (fn [x]
                    (if (string? x)
                      (sanitize-value pipeline x)
                      x))
                  step1)
                step1)]
    step2))

(defn sanitize-events
  "Sanitize a batch of events"
  [pipeline events]
  (map #(sanitize-event pipeline %) events))

;; ============================================================================
;; Specialized Sanitizers - Network
;; ============================================================================

(def sensitive-http-headers
  "HTTP headers that typically contain sensitive data"
  #{"authorization" "cookie" "set-cookie" "x-api-key" "x-auth-token"
    "x-access-token" "x-csrf-token" "proxy-authorization"})

(defn sanitize-http-headers
  "Sanitize sensitive HTTP headers"
  [headers]
  (when headers
    (into {}
      (for [[k v] headers]
        (if (contains? sensitive-http-headers (str/lower-case (name k)))
          [k "[REDACTED]"]
          [k v])))))

(defn sanitize-packet-payload
  "Sanitize HTTP-like payload content"
  [payload]
  (when payload
    (-> payload
        ;; Redact Authorization headers
        (str/replace #"(?i)Authorization:\s*\S+" "Authorization: [REDACTED]")
        ;; Redact cookies
        (str/replace #"(?i)Cookie:\s*[^\r\n]+" "Cookie: [REDACTED]")
        ;; Redact Set-Cookie
        (str/replace #"(?i)Set-Cookie:\s*[^\r\n]+" "Set-Cookie: [REDACTED]")
        ;; Redact form passwords
        (str/replace #"(?i)(password|passwd)=[^&\s]+" "$1=[REDACTED]")
        ;; Redact JSON passwords
        (str/replace #"(?i)\"(password|passwd|secret)\"\s*:\s*\"[^\"]*\""
                     "\"$1\": \"[REDACTED]\"")
        ;; Redact Bearer tokens
        (str/replace #"(?i)Bearer\s+[\w.-]+" "Bearer [REDACTED]")
        ;; Redact Basic auth
        (str/replace #"(?i)Basic\s+[\w+/=]+" "Basic [REDACTED]"))))

(defn sanitize-network-event
  "Sanitize a network event"
  [pipeline event]
  (-> event
      (update :payload sanitize-packet-payload)
      (update :headers sanitize-http-headers)
      (update :src-ip #(when % (mask-ip-address %)))
      (update :dst-ip #(when % (mask-ip-address %)))
      (sanitize-event pipeline)))

;; ============================================================================
;; Specialized Sanitizers - Process
;; ============================================================================

(defn sanitize-command-line
  "Sanitize sensitive data in command line arguments"
  [cmdline]
  (when cmdline
    (-> cmdline
        ;; Password arguments
        (str/replace #"(?i)(-p|--password)[=\s]+\S+" "$1=[REDACTED]")
        ;; Token arguments
        (str/replace #"(?i)(-t|--token)[=\s]+\S+" "$1=[REDACTED]")
        ;; API key arguments
        (str/replace #"(?i)(--api-key|--apikey)[=\s]+\S+" "$1=[REDACTED]")
        ;; Secret arguments
        (str/replace #"(?i)(--secret)[=\s]+\S+" "$1=[REDACTED]")
        ;; Database connection strings with passwords
        (str/replace #"(?i)(mysql|postgres|mongodb)://[^:]+:[^@]+@"
                     "$1://[USER]:[REDACTED]@")
        ;; Environment variable assignments
        (str/replace #"(?i)(PASSWORD|SECRET|TOKEN|API_KEY|AWS_SECRET)=\S+"
                     "$1=[REDACTED]"))))

(def sensitive-env-vars
  "Environment variable names that contain sensitive data"
  #{"PASSWORD" "SECRET" "TOKEN" "API_KEY" "AWS_SECRET" "AWS_ACCESS_KEY"
    "DATABASE_PASSWORD" "DB_PASSWORD" "PRIVATE_KEY" "SSH_KEY"
    "GITHUB_TOKEN" "NPM_TOKEN" "DOCKER_PASSWORD"})

(defn sanitize-environment
  "Sanitize sensitive environment variables"
  [env-vars]
  (when env-vars
    (into {}
      (for [[k v] env-vars]
        (if (some #(str/includes? (str/upper-case (name k)) %)
                  sensitive-env-vars)
          [k "[REDACTED]"]
          [k v])))))

(defn sanitize-process-event
  "Sanitize a process event"
  [pipeline event]
  (-> event
      (update :cmdline sanitize-command-line)
      (update :env sanitize-environment)
      (sanitize-event pipeline)))

;; ============================================================================
;; Pipeline Statistics
;; ============================================================================

(defn get-pipeline-stats
  "Get pipeline statistics"
  [pipeline]
  @(:stats pipeline))

(defn display-pipeline-stats
  "Display pipeline statistics"
  [pipeline]
  (let [stats (get-pipeline-stats pipeline)]
    (println "\n=== Sanitization Pipeline Statistics ===")
    (println (format "Events processed:  %d" (:events-processed stats)))
    (println (format "Fields sanitized:  %d" (:fields-sanitized stats)))
    (println (format "Patterns matched:  %d" (:patterns-matched stats)))
    (println (format "Bytes processed:   %d" (:bytes-processed stats)))))

(defn reset-pipeline-stats
  "Reset pipeline statistics"
  [pipeline]
  (reset! (:stats pipeline)
          {:events-processed 0
           :fields-sanitized 0
           :patterns-matched 0
           :bytes-processed 0}))

;; ============================================================================
;; Exercises
;; ============================================================================

(defn exercise-custom-rules
  "Exercise 1: Add custom sanitization rules"
  []
  (println "\n=== Exercise 1: Custom Sanitization Rules ===\n")

  ;; Define custom patterns
  (def custom-patterns
    {:employee-id #"\bEMP-\d{6}\b"
     :project-code #"\bPRJ-[A-Z]{3}-\d{4}\b"
     :internal-ip #"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"})

  ;; Create pipeline with custom config
  (let [custom-config {:strategies (merge (:strategies default-sanitization-config)
                                          {:employee-id :mask
                                           :project-code :redact
                                           :internal-ip :mask})
                       :custom-patterns custom-patterns}
        pipeline (create-sanitization-pipeline custom-config)]

    ;; Test custom rules
    (let [test-text "Employee EMP-123456 working on PRJ-ABC-2024 from 10.0.1.50"]
      (println "Original text:")
      (println (format "  %s" test-text))

      ;; Apply custom pattern sanitization
      (let [result (reduce
                     (fn [t [data-type pattern]]
                       (str/replace t pattern
                                    (str "[CUSTOM:" (name data-type) "]")))
                     test-text
                     custom-patterns)]
        (println "\nSanitized text:")
        (println (format "  %s" result))))))

(defn exercise-reversible-tokenization
  "Exercise 2: Implement reversible tokenization"
  []
  (println "\n=== Exercise 2: Reversible Tokenization ===\n")

  (let [tokenizer (create-tokenizer)
        tokenize (:tokenize tokenizer)
        detokenize (:detokenize tokenizer)
        get-mapping (:get-mapping tokenizer)]

    ;; Tokenize some values
    (println "Tokenizing sensitive values...")
    (let [values ["user@example.com"
                  "secret-api-key-12345"
                  "192.168.1.100"
                  "user@example.com"]] ; Same email again

      (println "\nTokenization results:")
      (doseq [v values]
        (let [token (tokenize v)]
          (println (format "  '%s' -> '%s'" v token))))

      ;; Verify consistency
      (println "\nVerifying tokenization consistency:")
      (let [email "user@example.com"
            token1 (tokenize email)
            token2 (tokenize email)]
        (println (format "  Same value tokenized twice: %s"
                         (if (= token1 token2) "CONSISTENT" "INCONSISTENT"))))

      ;; Demonstrate detokenization
      (println "\nDetokenization:")
      (doseq [[original token] (get-mapping)]
        (let [recovered (detokenize token)]
          (println (format "  '%s' <- '%s' (matches: %s)"
                           recovered token
                           (if (= original recovered) "YES" "NO"))))))))

(defn exercise-audit-trail
  "Exercise 3: Add audit logging for sanitization operations"
  []
  (println "\n=== Exercise 3: Sanitization Audit Trail ===\n")

  (let [audit-log (atom [])
        pipeline (create-sanitization-pipeline {})]

    ;; Wrap sanitization with auditing
    (defn audited-sanitize-event [event]
      (let [sensitive-fields (scan-event-for-sensitive-fields event)
            content-detections (when-let [msg (:message event)]
                                 (detect-sensitive-data msg))
            start-time (System/nanoTime)
            result (sanitize-event pipeline event)
            duration-ns (- (System/nanoTime) start-time)]

        ;; Log audit entry
        (swap! audit-log conj
               {:timestamp (java.time.Instant/now)
                :event-type (:type event)
                :sensitive-fields-found (count sensitive-fields)
                :content-patterns-found (count content-detections)
                :duration-ns duration-ns
                :fields-sanitized (when (seq sensitive-fields)
                                    (map name sensitive-fields))
                :patterns-matched (when (seq content-detections)
                                    (map :type content-detections))})
        result))

    ;; Process some test events
    (let [events [{:type :login
                   :username "alice"
                   :password "secret123"
                   :message "Login from 192.168.1.100"}
                  {:type :api-call
                   :api-key "sk_live_abc123"
                   :endpoint "/users"
                   :message "API call with token=xyz789"}
                  {:type :normal
                   :action "view"
                   :resource "/public/docs"}]]

      (println "Processing events with audit...")
      (doseq [event events]
        (audited-sanitize-event event))

      ;; Display audit report
      (println "\n--- Sanitization Audit Report ---\n")
      (println (format "Total events processed: %d" (count @audit-log)))

      (println "\nPer-event details:")
      (doseq [[idx entry] (map-indexed vector @audit-log)]
        (println (format "\n  Event %d (%s):" (inc idx) (:event-type entry)))
        (println (format "    Sensitive fields: %d" (:sensitive-fields-found entry)))
        (println (format "    Content patterns: %d" (:content-patterns-found entry)))
        (println (format "    Processing time:  %.3f ms" (/ (:duration-ns entry) 1e6)))
        (when (seq (:fields-sanitized entry))
          (println (format "    Fields sanitized: %s"
                           (str/join ", " (:fields-sanitized entry)))))
        (when (seq (:patterns-matched entry))
          (println (format "    Patterns matched: %s"
                           (str/join ", " (map name (:patterns-matched entry)))))))

      ;; Summary statistics
      (println "\n--- Summary ---")
      (println (format "Total sensitive fields found: %d"
                       (reduce + (map :sensitive-fields-found @audit-log))))
      (println (format "Total patterns matched: %d"
                       (reduce + (map :content-patterns-found @audit-log)))))))

;; ============================================================================
;; Test Functions
;; ============================================================================

(defn test-pattern-detection []
  (println "Testing pattern detection...")

  ;; Test password detection
  (assert (contains-sensitive-data? "password=secret123")
          "Should detect password")
  (assert (contains-sensitive-data? "api_key: abc123xyz")
          "Should detect API key")
  (assert (contains-sensitive-data? "1234-5678-9012-3456")
          "Should detect credit card")
  (assert (contains-sensitive-data? "user@example.com")
          "Should detect email")
  (assert (not (contains-sensitive-data? "Hello World"))
          "Should not detect in clean text")

  ;; Test detection details
  (let [detections (detect-sensitive-data
                     "Login: user@example.com, password=secret, card 4111-1111-1111-1234")]
    (assert (>= (count detections) 3) "Should detect multiple patterns"))

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
    (assert (= "192.168.1.xxx" (mask-ip-address "192.168.1.100"))
            "IP should be masked")
    (assert (= "(***) ***-4567" (mask-phone "555-123-4567"))
            "Phone should be masked")

    (println "Sanitization tests passed!")))

(defn test-specialized-sanitizers []
  (println "Testing specialized sanitizers...")

  ;; Test command line sanitization
  (let [cmdline "curl -u user:secret --password mypass http://example.com"
        result (sanitize-command-line cmdline)]
    (assert (str/includes? result "REDACTED")
            "Command line passwords should be redacted")
    (assert (not (str/includes? result "mypass"))
            "Should not contain 'mypass'"))

  ;; Test HTTP header sanitization
  (let [headers {"Authorization" "Bearer token123"
                 "Content-Type" "application/json"
                 "Cookie" "session=abc"}
        result (sanitize-http-headers headers)]
    (assert (= "[REDACTED]" (get result "Authorization"))
            "Authorization should be redacted")
    (assert (= "application/json" (get result "Content-Type"))
            "Content-Type should not be changed"))

  ;; Test environment sanitization
  (let [env {"PATH" "/usr/bin"
             "DATABASE_PASSWORD" "secret123"
             "HOME" "/home/user"}
        result (sanitize-environment env)]
    (assert (= "[REDACTED]" (get result "DATABASE_PASSWORD"))
            "DATABASE_PASSWORD should be redacted")
    (assert (= "/usr/bin" (get result "PATH"))
            "PATH should not be changed"))

  (println "Specialized sanitizer tests passed!"))

(defn run-demo []
  (println "\n=== Demo: Sanitizing Sample Events ===\n")

  (let [pipeline (create-sanitization-pipeline {})
        events [{:type :login
                 :username "alice"
                 :password "supersecret"
                 :ip "192.168.1.100"}
                {:type :api-call
                 :api-key "sk_live_abc123xyz"
                 :endpoint "/users"
                 :message "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc"}
                {:type :payment
                 :card "4111-1111-1111-1234"
                 :amount 99.99
                 :email "customer@example.com"}
                {:type :message
                 :content "Contact me at user@example.com or 555-123-4567, my SSN is 123-45-6789"}
                {:type :process
                 :cmdline "mysql -u root --password=dbsecret database"
                 :env {"DB_PASSWORD" "secret123"
                       "PATH" "/usr/bin"}}]]

    (println "Original events:")
    (doseq [event events]
      (println (format "  %s" (pr-str event))))

    (let [sanitized (sanitize-events pipeline events)]
      (println "\nSanitized events:")
      (doseq [event sanitized]
        (println (format "  %s" (pr-str event)))))

    (display-pipeline-stats pipeline)))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the data sanitization lab"
  [& args]
  (println "Lab 17.2: Data Sanitization Pipeline")
  (println "====================================\n")

  (let [command (first args)]
    (case command
      "test"
      (do
        (test-pattern-detection)
        (test-sanitization)
        (test-specialized-sanitizers)
        (println "\nAll tests passed!"))

      "demo"
      (run-demo)

      "exercise1"
      (exercise-custom-rules)

      "exercise2"
      (exercise-reversible-tokenization)

      "exercise3"
      (exercise-audit-trail)

      ;; Default: run all
      (do
        (test-pattern-detection)
        (test-sanitization)
        (test-specialized-sanitizers)
        (run-demo)
        (exercise-custom-rules)
        (exercise-reversible-tokenization)
        (exercise-audit-trail)

        (println "\n=== Key Takeaways ===")
        (println "1. Use regex patterns to detect sensitive data in text")
        (println "2. Apply appropriate strategies: redact, mask, hash, or tokenize")
        (println "3. Sanitize both field names and content")
        (println "4. Use specialized sanitizers for network and process events")
        (println "5. Maintain audit trails for compliance")))))

;; Run with: clj -M -m lab-17-2-data-sanitization
