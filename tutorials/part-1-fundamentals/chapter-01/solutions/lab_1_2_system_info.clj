(ns lab-1-2-system-info
  "Lab 1.2: System Information - Query eBPF capabilities

   This solution demonstrates:
   - Querying kernel version and features
   - Checking BPF filesystem status
   - Discovering available helper functions
   - Checking architecture information
   - Verifying eBPF feature support

   Run with: clojure -M -m lab-1-2-system-info
   Note: Some features require root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.arch :as arch]
            [clj-ebpf.helpers :as helpers]
            [clojure.java.io :as io]))

;;; Kernel Version Utilities

(defn format-kernel-version
  "Format kernel version integer as human-readable string.
   Kernel version is encoded as: (major << 16) | (minor << 8) | patch"
  [version]
  (let [major (bit-shift-right (bit-and version 0xFF0000) 16)
        minor (bit-shift-right (bit-and version 0x00FF00) 8)
        patch (bit-and version 0x0000FF)]
    (format "%d.%d.%d" major minor patch)))

(defn parse-kernel-version
  "Parse kernel version string to integer.
   Example: \"5.15.0\" -> 0x050f00"
  [version-str]
  (let [[major minor patch] (map #(Integer/parseInt %)
                                  (clojure.string/split version-str #"\."))]
    (bit-or (bit-shift-left major 16)
            (bit-shift-left minor 8)
            (or patch 0))))

;;; Feature Detection

(def kernel-features
  "Map of eBPF features and their minimum kernel versions"
  {:basic-bpf      {:version 0x031200 :name "Basic BPF"}
   :bpf-maps       {:version 0x040100 :name "BPF Maps"}
   :tail-calls     {:version 0x040400 :name "Tail Calls"}
   :tracepoints    {:version 0x040700 :name "Tracepoint Support"}
   :xdp            {:version 0x040800 :name "XDP (eXpress Data Path)"}
   :cgroup-bpf     {:version 0x040A00 :name "Cgroup BPF"}
   :btf            {:version 0x040E00 :name "BTF (BPF Type Format)"}
   :cap-bpf        {:version 0x050800 :name "CAP_BPF Capability"}
   :ringbuf        {:version 0x050800 :name "Ring Buffers"}
   :sleepable-bpf  {:version 0x050A00 :name "Sleepable BPF"}
   :lsm-bpf        {:version 0x050700 :name "LSM BPF Hooks"}})

(defn check-kernel-features
  "Check which eBPF features are available based on kernel version"
  [kernel-version]
  (into {}
        (for [[feature {:keys [version name]}] kernel-features]
          [feature {:available (>= kernel-version version)
                    :name name
                    :min-version (format-kernel-version version)}])))

;;; BPF Filesystem

(defn check-bpf-filesystem
  "Check if BPF filesystem is mounted"
  []
  (let [bpf-fs-path "/sys/fs/bpf"
        exists? (.exists (io/file bpf-fs-path))
        is-dir? (and exists? (.isDirectory (io/file bpf-fs-path)))]
    {:mounted (and exists? is-dir?)
     :path bpf-fs-path
     :readable (and exists? (.canRead (io/file bpf-fs-path)))}))

;;; Helper Functions

(defn display-helper-summary
  "Display summary of available helper functions by category"
  []
  (let [all-helpers (helpers/all-helpers)
        by-category (group-by (fn [[_ v]] (:category v)) all-helpers)
        categories [:map :probe :time :process :cpu :stack :perf :ringbuf
                    :debug :control :cgroup :sync :util :network :socket
                    :lsm :security]]
    (println "\nHelper Functions by Category:")
    (println (apply str (repeat 40 "-")))
    (doseq [cat categories]
      (let [cat-helpers (get by-category cat [])]
        (when (seq cat-helpers)
          (println (format "  %-15s: %3d helpers" (name cat) (count cat-helpers))))))
    (println (format "\n  Total: %d helpers available" (count all-helpers)))))

(defn display-sample-helpers
  "Display details for commonly used helper functions"
  []
  (println "\nSample Helper Functions:")
  (println (apply str (repeat 40 "-")))
  (let [sample-helpers [:map-lookup-elem :get-current-pid-tgid
                        :ktime-get-ns :probe-read-kernel
                        :perf-event-output :ringbuf-output]]
    (doseq [helper-key sample-helpers]
      (when-let [info (helpers/get-helper-info helper-key)]
        (println (format "\n  %s (ID: %d)"
                         (:name info)
                         (:id info)))
        (println (format "    Min Kernel: %s" (:min-kernel info "unknown")))
        (println (format "    Category: %s" (name (:category info))))
        (when-let [desc (:description info)]
          (println (format "    %s" desc)))))))

;;; Capability Checks

(defn check-bpf-capability
  "Check if we can load BPF programs"
  []
  (try
    (let [test-prog (bpf/assemble [(bpf/mov :r0 0) (bpf/exit-insn)])
          prog-fd (bpf/load-program {:prog-type :socket-filter :insns test-prog})]
      (bpf/close-program prog-fd)
      {:can-load true :error nil})
    (catch Exception e
      {:can-load false :error (.getMessage e)})))

;;; Challenge Solution

(defn check-helper-requirements
  "Challenge: Determine minimum kernel version needed for a list of helpers"
  [helper-keys]
  (let [helper-infos (map helpers/get-helper-info helper-keys)
        min-versions (keep :min-kernel helper-infos)
        parsed-versions (map parse-kernel-version min-versions)
        max-required (if (seq parsed-versions)
                       (apply max parsed-versions)
                       0)
        init-result (bpf/init!)
        current-version (:kernel-version init-result)
        missing (filter (fn [k]
                          (when-let [info (helpers/get-helper-info k)]
                            (when-let [min-ver (:min-kernel info)]
                              (< current-version (parse-kernel-version min-ver)))))
                        helper-keys)]
    {:min-kernel (format-kernel-version max-required)
     :current-kernel (format-kernel-version current-version)
     :supported? (>= current-version max-required)
     :missing (vec missing)}))

;;; Main Functions

(defn run-lab []
  (println "=== Lab 1.2: System Information ===\n")

  ;; Step 1: Initialize and get kernel version
  (println "Step 1: Querying kernel version...")
  (let [init-result (bpf/init!)
        kernel-version (:kernel-version init-result)]
    (println "  Kernel version (hex):" (format "0x%06x" kernel-version))
    (println "  Kernel version:" (format-kernel-version kernel-version))

    ;; Step 2: Check BPF filesystem
    (println "\nStep 2: Checking BPF filesystem...")
    (let [fs-info (check-bpf-filesystem)]
      (if (:mounted fs-info)
        (do
          (println (format "  BPF filesystem mounted at %s" (:path fs-info)))
          (println (format "  Readable: %s" (if (:readable fs-info) "yes" "no"))))
        (println (format "  BPF filesystem NOT mounted at %s" (:path fs-info)))))

    ;; Step 3: Check architecture
    (println "\nStep 3: Checking system architecture...")
    (println "  Architecture:" arch/arch-name)
    (println "  Arch keyword:" arch/current-arch)
    (println "  BPF syscall:" (arch/get-syscall-nr :bpf))

    ;; Step 4: Check eBPF features
    (println "\nStep 4: Checking eBPF feature support...")
    (let [features (check-kernel-features kernel-version)
          ;; Create ordered list based on original kernel-features versions
          ordered-features (sort-by (fn [[k _]] (get-in kernel-features [k :version]))
                                    features)]
      (println "\n  Feature                  Available  Min Kernel")
      (println "  " (apply str (repeat 50 "-")))
      (doseq [[_ {:keys [available name min-version]}] ordered-features]
        (println (format "  %-24s %-10s %s"
                         name
                         (if available "yes" "no")
                         min-version))))

    ;; Step 5: Query helper functions
    (println "\nStep 5: Querying helper functions...")
    (display-helper-summary)
    (display-sample-helpers)

    ;; Step 6: Check BPF capability
    (println "\nStep 6: Checking BPF capabilities...")
    (let [cap-result (check-bpf-capability)]
      (if (:can-load cap-result)
        (println "  Can load BPF programs: yes")
        (do
          (println "  Can load BPF programs: no")
          (println "  Error:" (:error cap-result)))))

    (println "\n=== Lab 1.2 Complete! ===")
    true))

(defn run-challenge []
  (println "\n=== Lab 1.2 Challenge: Helper Requirements ===\n")

  (let [test-helpers [:map-lookup-elem :ringbuf-output :probe-read-kernel]
        result (check-helper-requirements test-helpers)]
    (println "Checking helpers:" test-helpers)
    (println "\nResults:")
    (println "  Minimum kernel required:" (:min-kernel result))
    (println "  Current kernel:" (:current-kernel result))
    (println "  All supported?:" (if (:supported? result) "yes" "no"))
    (when (seq (:missing result))
      (println "  Missing helpers:" (:missing result)))

    (println "\n=== Challenge Complete! ===")))

(defn -main [& args]
  (run-lab)
  (run-challenge)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)
  (run-challenge)

  ;; Experiment: Check specific helpers
  (check-helper-requirements [:map-lookup-elem :ktime-get-ns])

  ;; Experiment: List all map helpers
  (filter (fn [[k v]] (= :map (:category v))) (helpers/all-helpers))

  ;; Experiment: Find helpers introduced in kernel 5.8+
  (filter (fn [[k v]]
            (when-let [min-ver (:min-kernel v)]
              (>= (parse-kernel-version min-ver) 0x050800)))
          (helpers/all-helpers))
  )
