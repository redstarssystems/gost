(ns org.rssys.gost.armor
  "Functions to work with armored messages"
  (:require
    [clojure.java.io :as io]
    [clojure.string :as string]
    [clojure.walk :as walk]
    [org.rssys.gost.pem :as p]
    [org.rssys.gost.sign :as s])
  (:import
    (java.io
      ByteArrayOutputStream)
    (java.time
      ZonedDateTime)
    (java.time.format
      DateTimeFormatter)
    (org.bouncycastle.jcajce.provider.asymmetric.ecgost12
      BCECGOST3410_2012PrivateKey
      BCECGOST3410_2012PublicKey)))


(def ^:const start-line "-----[ START DATA ]-----\n")
(def ^:const end-line "\n-----[ END DATA ]-----\n")


(defn sign-message
  "Sign text message and headers data with PrivateKey.
  `headers` - an optional map where only string and keywords are allowed (no nested maps).
  `time` of signature is always added to headers.
  `datetime-formatter` is optional parameter should be of ^java.time.format.DateTimeFormatter class
  Returns armored text message with signature."
  ^String
  [^BCECGOST3410_2012PrivateKey private-key ^String message & {:keys [headers datetime-formatter]}]
  (let [time-formatter    (or datetime-formatter (DateTimeFormatter/ofPattern "yyyy-MM-dd HH:mm:ss"))
        sign-time         (.format
                            time-formatter
                            (ZonedDateTime/now))
        headers-str       (when headers                     ;; convert all keywords to strings
                            (walk/postwalk (fn [x] (cond (keyword? x) (name x) :else x)) headers))
        _                 (when headers                     ;; check all values are strings
                            (when-not (every? (fn [[_ v]] (string? v)) headers-str)
                              (throw (ex-info "Only string are allowed as values" {:headers headers}))))
        input             (if headers
                            (.getBytes (str message sign-time headers-str))
                            (.getBytes (str message sign-time)))
        sign-fn           (if (= 256 (s/-key-length private-key)) s/sign-256 s/sign-512)
        signature         (sign-fn private-key input)
        attached-pem-sign (p/write-struct-to-pem {:data    signature
                                                  :type    "SIGNATURE"
                                                  :headers (merge headers {:time sign-time})})
        baos              (ByteArrayOutputStream.)
        out               (io/output-stream baos)]
    (.write out (.getBytes start-line))
    (.write out (.getBytes message))
    (.write out (.getBytes end-line))
    (.write out (.getBytes attached-pem-sign))
    (.close out)
    (String. (.toByteArray baos))))



(defn read-armored-body
  "Returns plain message from armored signed message"
  ^String
  [^String pem-body]
  (let [last-index (string/index-of pem-body end-line)]
    (-> pem-body
      (subs 0 last-index)
      (string/replace start-line ""))))


(defn verify-message
  "Verify armored message and headers data with PublicKey.
  Returns ^String message if signature for headers and message is valid. Throws exception if signature is not valid."
  ^String
  [^BCECGOST3410_2012PublicKey public-key ^String armored-message]
  (let [message       (read-armored-body armored-message)
        struct        (p/read-struct-from-pem armored-message)
        signature     (:data struct)
        sign-time     (-> struct :headers (get "time"))
        headers       (dissoc (:headers struct) "time")
        input         (if (seq headers)
                        (.getBytes (str message sign-time headers))
                        (.getBytes (str message sign-time)))
        verify-fn     (if (= 256 (s/-key-length public-key)) s/verify-256 s/verify-512)
        signature-ok? (verify-fn public-key input signature)]
    (if signature-ok?
      message
      (throw (ex-info "Signature is not valid" {:time sign-time})))))


