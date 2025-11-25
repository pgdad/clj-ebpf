(ns clj-ebpf.helpers
  "BPF helper function metadata and utilities.

   Helper metadata is loaded from resources/bpf-helpers.edn, which allows
   easy extension and customization without code changes.

   Usage:
   - (get-helper-info :map-lookup-elem) - Get metadata for a helper
   - (get-helper-id :ktime-get-ns) - Get helper function ID
   - (helpers-by-category :network) - Get all network helpers
   - (available-helpers :xdp \"5.8\") - Get helpers for program type and kernel"
  (:require [clj-ebpf.utils :as utils]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]))

;; ============================================================================
;; Helper Metadata Loading
;; ============================================================================

(defn- load-helpers-from-resource
  "Load helper metadata from EDN resource file"
  []
  (if-let [resource (io/resource "bpf-helpers.edn")]
    (with-open [r (java.io.PushbackReader. (io/reader resource))]
      (edn/read r))
    (throw (ex-info "Could not find bpf-helpers.edn resource"
                    {:resource "bpf-helpers.edn"}))))

(def helper-metadata
  "Complete registry of BPF helper functions with metadata.
   Loaded from resources/bpf-helpers.edn at runtime."
  (delay (load-helpers-from-resource)))

(defn reload-helpers!
  "Reload helper metadata from resource file.
   Useful for development or after adding custom helpers."
  []
  (alter-var-root #'helper-metadata (constantly (delay (load-helpers-from-resource))))
  :reloaded)

;; ============================================================================
;; Custom Helper Registration
;; ============================================================================

(def ^:private custom-helpers
  "User-defined custom helpers"
  (atom {}))

(defn register-custom-helper!
  "Register a custom helper function.

   Example:
   (register-custom-helper! :my-helper
     {:id 1000
      :name \"my_custom_helper\"
      :signature {:return :long :args [:ctx-ptr :arg1]}
      :min-kernel \"5.15\"
      :prog-types :all
      :category :custom
      :description \"My custom helper function\"})"
  [helper-key helper-info]
  (when-not (and (:id helper-info)
                 (:name helper-info)
                 (:signature helper-info))
    (throw (ex-info "Helper info must include :id, :name, and :signature"
                    {:helper-key helper-key :provided (keys helper-info)})))
  (swap! custom-helpers assoc helper-key helper-info)
  helper-key)

(defn unregister-custom-helper!
  "Remove a custom helper"
  [helper-key]
  (swap! custom-helpers dissoc helper-key)
  helper-key)

(defn clear-custom-helpers!
  "Remove all custom helpers"
  []
  (reset! custom-helpers {})
  :cleared)

;; ============================================================================
;; Helper Query Functions
;; ============================================================================

(defn all-helpers
  "Get all helpers including custom ones"
  []
  (merge @helper-metadata @custom-helpers))

(defn get-helper-info
  "Get metadata for a helper function by keyword.
   Checks custom helpers first, then built-in helpers."
  [helper-key]
  (or (get @custom-helpers helper-key)
      (get @helper-metadata helper-key)))

(defn get-helper-id
  "Get helper function ID by keyword"
  [helper-key]
  (:id (get-helper-info helper-key)))

(defn get-helper-by-id
  "Look up helper by numeric ID"
  [id]
  (first (filter #(= id (:id (second %))) (all-helpers))))

(defn get-helper-by-name
  "Look up helper by C function name"
  [name]
  (first (filter #(= name (:name (second %))) (all-helpers))))

(defn helpers-by-category
  "Get all helpers in a category"
  [category]
  (filter #(= (:category (second %)) category) (all-helpers)))

(defn list-categories
  "List all helper categories"
  []
  (sort (distinct (map #(:category (second %)) (all-helpers)))))

(defn available-helpers
  "Get helpers compatible with program type and kernel version"
  ([prog-type]
   (filter (fn [[k v]]
             (let [types (:prog-types v)]
               (or (= types :all)
                   (contains? types prog-type))))
           (all-helpers)))
  ([prog-type kernel-version]
   (filter (fn [[k v]]
             (and (or (= (:prog-types v) :all)
                      (contains? (:prog-types v) prog-type))
                  (<= (utils/parse-kernel-version (:min-kernel v))
                      (utils/parse-kernel-version kernel-version))))
           (all-helpers))))

(defn helper-compatible?
  "Check if helper is compatible with program type and kernel version"
  [helper-key prog-type kernel-version]
  (when-let [info (get-helper-info helper-key)]
    (and (or (= (:prog-types info) :all)
             (contains? (:prog-types info) prog-type))
         (<= (utils/parse-kernel-version (:min-kernel info))
             (utils/parse-kernel-version kernel-version)))))

;; ============================================================================
;; Helper Search
;; ============================================================================

(defn search-helpers
  "Search helpers by name or description.
   Returns helpers where query matches name or description (case-insensitive)."
  [query]
  (let [q (str/lower-case query)]
    (filter (fn [[k v]]
              (or (str/includes? (str/lower-case (name k)) q)
                  (str/includes? (str/lower-case (:name v)) q)
                  (str/includes? (str/lower-case (:description v)) q)))
            (all-helpers))))

(defn helpers-since-kernel
  "Get helpers introduced in or after a specific kernel version"
  [kernel-version]
  (let [target (utils/parse-kernel-version kernel-version)]
    (filter (fn [[k v]]
              (>= (utils/parse-kernel-version (:min-kernel v)) target))
            (all-helpers))))

(defn helpers-until-kernel
  "Get helpers available up to a specific kernel version"
  [kernel-version]
  (let [target (utils/parse-kernel-version kernel-version)]
    (filter (fn [[k v]]
              (<= (utils/parse-kernel-version (:min-kernel v)) target))
            (all-helpers))))

;; ============================================================================
;; Helper Information Display
;; ============================================================================

(defn print-helper-info
  "Print formatted helper information"
  [helper-key]
  (when-let [info (get-helper-info helper-key)]
    (println "========================================")
    (println "BPF Helper:" (:name info))
    (println "========================================")
    (println "ID:" (:id info))
    (println "Category:" (:category info))
    (println "Min Kernel:" (:min-kernel info))
    (println "Program Types:" (if (= (:prog-types info) :all)
                                "all"
                                (str/join ", " (map name (:prog-types info)))))
    (println "Return Type:" (:return (:signature info)))
    (println "Arguments:" (str/join ", " (map name (:args (:signature info)))))
    (println "Description:" (:description info))
    (println "========================================")))

(defn list-helpers
  "List all helpers, optionally filtered by category"
  ([]
   (doseq [[k v] (sort-by #(:id (second %)) (all-helpers))]
     (println (format "%-30s [%3d] %s" (:name v) (:id v) (:description v)))))
  ([category]
   (doseq [[k v] (sort-by #(:id (second %)) (helpers-by-category category))]
     (println (format "%-30s [%3d] %s" (:name v) (:id v) (:description v))))))

(defn list-helpers-for-program
  "List helpers available for a specific program type and kernel version"
  [prog-type kernel-version]
  (println (format "Helpers available for %s on kernel %s:"
                   (name prog-type) kernel-version))
  (println "")
  (doseq [[k v] (sort-by #(:id (second %))
                         (available-helpers prog-type kernel-version))]
    (println (format "  %-30s [%3d] %s" (:name v) (:id v) (:description v)))))

;; ============================================================================
;; Helper Statistics
;; ============================================================================

(defn helper-stats
  "Get statistics about available helpers"
  []
  (let [helpers (all-helpers)
        by-category (group-by #(:category (second %)) helpers)
        by-kernel (group-by #(:min-kernel (second %)) helpers)]
    {:total (count helpers)
     :built-in (count @helper-metadata)
     :custom (count @custom-helpers)
     :categories (into {} (map (fn [[k v]] [k (count v)]) by-category))
     :by-kernel-version (into (sorted-map)
                              (map (fn [[k v]] [k (count v)]) by-kernel))}))

(defn print-helper-stats
  "Print helper statistics"
  []
  (let [stats (helper-stats)]
    (println "=== BPF Helper Statistics ===")
    (println "Total helpers:" (:total stats))
    (println "  Built-in:" (:built-in stats))
    (println "  Custom:" (:custom stats))
    (println "")
    (println "By category:")
    (doseq [[cat cnt] (sort-by second > (:categories stats))]
      (println (format "  %-15s %3d" (name cat) cnt)))
    (println "")
    (println "By minimum kernel version:")
    (doseq [[ver cnt] (:by-kernel-version stats)]
      (println (format "  %-10s %3d" ver cnt)))))
