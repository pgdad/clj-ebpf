(ns build
  "Build script for clj-ebpf library.

   Usage:
     clj -T:build clean       # Clean target directory
     clj -T:build jar         # Build JAR file
     clj -T:build install     # Install to local Maven repository
     clj -T:build deploy      # Deploy to Clojars

   Environment variables for deployment:
     CLOJARS_USERNAME - Your Clojars username
     CLOJARS_PASSWORD - Your Clojars deploy token (not password!)

   To get a deploy token:
     1. Log in to https://clojars.org
     2. Go to your profile settings
     3. Generate a deploy token"
  (:require [clojure.tools.build.api :as b]
            [deps-deploy.deps-deploy :as dd]))

(def lib 'org.clojars.pgdad/clj-ebpf)
;; Use RELEASE_VERSION env var if set, otherwise use git commit count
(def version (or (System/getenv "RELEASE_VERSION")
                 (format "0.1.%s" (b/git-count-revs nil))))
(def class-dir "target/classes")
(def jar-file (format "target/%s-%s.jar" (name lib) version))

;; Read basis from deps.edn
(def basis (delay (b/create-basis {:project "deps.edn"})))

(defn clean
  "Delete the target directory."
  [_]
  (b/delete {:path "target"})
  (println "Cleaned target directory"))

(defn jar
  "Build the JAR file."
  [_]
  (clean nil)
  (println (str "Building " jar-file))
  (b/write-pom {:class-dir class-dir
                :lib lib
                :version version
                :basis @basis
                :src-dirs ["src"]
                :resource-dirs ["resources"]
                :scm {:url "https://github.com/pgdad/clj-ebpf"
                      :connection "scm:git:git://github.com/pgdad/clj-ebpf.git"
                      :developerConnection "scm:git:ssh://git@github.com/pgdad/clj-ebpf.git"
                      :tag (str "v" version)}
                :pom-data [[:description "A Clojure DSL for eBPF programming using Java 25+ Panama FFI"]
                           [:url "https://github.com/pgdad/clj-ebpf"]
                           [:licenses
                            [:license
                             [:name "Eclipse Public License 2.0"]
                             [:url "https://www.eclipse.org/legal/epl-2.0/"]]]
                           [:developers
                            [:developer
                             [:name "Esa"]]]
                           [:properties
                            [:project.build.sourceEncoding "UTF-8"]]]})
  (b/copy-dir {:src-dirs ["src" "resources"]
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file jar-file})
  (println (str "Built " jar-file)))

(defn install
  "Install JAR to local Maven repository."
  [_]
  (jar nil)
  (println (str "Installing " jar-file " to local Maven repository"))
  (b/install {:basis @basis
              :lib lib
              :version version
              :jar-file jar-file
              :class-dir class-dir})
  (println "Installed successfully"))

(defn deploy
  "Deploy JAR to Clojars.

   Requires CLOJARS_USERNAME and CLOJARS_PASSWORD environment variables.
   CLOJARS_PASSWORD should be a deploy token, not your account password."
  [_]
  (jar nil)
  (println (str "Deploying " jar-file " to Clojars"))
  (dd/deploy {:installer :remote
              :artifact (b/resolve-path jar-file)
              :pom-file (b/pom-path {:lib lib :class-dir class-dir})})
  (println "Deployed successfully to Clojars"))
