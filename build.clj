(ns build
  (:refer-clojure :exclude [test])
  (:require
    [clojure.pprint :as pprint]
    [clojure.tools.build.api :as b]
    [org.corfield.build :as bb]))


(def artifact 'org.rssys/gost)
(def version "0.4.0")


;; (format "1.0.%s" (System/getenv "git-rev-count"))

(def project-env
  {:artifact            artifact
   :version             version
   :build-time          (System/getenv "build-time")
   :build-timestamp     (Long/parseLong (System/getenv "build-timestamp"))
   :target-folder       (System/getenv "target-folder")
   :release-branches    (System/getenv "release-branches")
   :deployable-branches (System/getenv "deployable-branches")
   :git-url             (System/getenv "git-url")
   :git-branch          (System/getenv "git-branch")
   :git-sha             (System/getenv "git-sha")
   :git-rev-count       (System/getenv "git-rev-count")
   :release?            (Boolean/parseBoolean (System/getenv "release?"))
   :snapshot?           (Boolean/parseBoolean (System/getenv "snapshot?"))
   :deployable?         (Boolean/parseBoolean (System/getenv "deployable?"))})


(println "Project settings:")
(clojure.pprint/pprint project-env)


(defn jar
  "Build the JAR."
  [opts]
  (let [opts (assoc opts :lib (:artifact project-env) :version (:version project-env))
        pom-path (str (bb/default-class-dir) "/"  (b/pom-path opts))]
    (-> opts
      (bb/jar))
    (b/copy-file {:src pom-path :target "./pom.xml"})))


(defn install
  "Install the JAR locally."
  [opts]
  (-> opts
    (assoc :lib (:artifact project-env) :version (:version project-env))
    (bb/install)))


(defn deploy
  "Deploy the JAR to Clojars."
  [opts]
  (-> opts
    (assoc :lib (:artifact project-env) :version (:version project-env))
    (bb/deploy)))
