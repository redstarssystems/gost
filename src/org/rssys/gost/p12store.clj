(ns org.rssys.gost.p12store
  "PKCS12 keystore functions"
  (:require
    [clojure.java.io :as io]
    [org.rssys.gost.encrypt :as e]
    [org.rssys.gost.sign :as s])
  (:import
    (java.security
      KeyStore
      KeyStore$PasswordProtection
      KeyStore$PrivateKeyEntry
      KeyStore$SecretKeyEntry
      PrivateKey)
    (java.security.cert
      X509Certificate)
    (javax.crypto.spec
      PBEParameterSpec
      SecretKeySpec)))


;; How many bytes is salt for PBE
(def ^:const pbe-salt-length 16)


;; Number of iterations during PBE
(def ^:const pbe-iter-count 12000)


(defn create-keystore
  "Create empty PKCS12 keystore in a memory."
  ^KeyStore
  []
  (doto (KeyStore/getInstance "PKCS12")
    (.load nil nil)))


(defn write-keystore
  "Write PKCS12 keystore to a file.
  Returns absolute path for filename if success or throws Exception if error."
  [^KeyStore ks ^String filename ^String password]
  (with-open [out (io/output-stream filename)]
    (.store ks out (char-array password)))
  (.getAbsolutePath (io/file filename)))


(defn read-keystore
  "Read PKCS12 keystore from file.
  Returns ^KeyStore object."
  ^KeyStore
  [^String filename ^String password]
  (let [in (io/input-stream filename)
        ks (KeyStore/getInstance "PKCS12")]
    (.load ks in (char-array password))
    (.close in)
    ks))


(defn list-aliases
  "Returns vector of aliases from KeyStore."
  [^KeyStore ks]
  (into [] (iterator-seq (.asIterator (.aliases ks)))))


(defn get-private-key
  "Get ^PrivateKey from KeyStore using given alias.
  Returns PrivateKey if the entry identified by the given alias was created by a call to setEntry with a PrivateKeyEntry.
  Password is an optional parameter, password for key entry, may be empty String."
  ^PrivateKey
  [^KeyStore ks ^String alias & {:keys [^String password] :or {password ""}}]
  (if (.isKeyEntry ks alias)
    (let [k (.getKey ks alias (char-array password))]
      (if (instance? PrivateKey k)
        k
        (throw (ex-info "Not a PrivateKey" {:alias alias}))))
    (throw (ex-info "Not a PrivateKeyEntry" {:alias alias}))))


(defn get-secret-key
  "Get ^SecretKey from KeyStore using given alias.
  Algorithm is changed from AES to GOST3412-2015, cause GOST3412-2015 is unknown for PKCS12 KeyStore.
  Password for key entry is an optional parameter, may be empty String."
  ^PrivateKey
  [^KeyStore ks ^String alias & {:keys [^String password] :or {password ""}}]
  (if (.isKeyEntry ks alias)
    (let [k (.getKey ks alias (char-array password))]
      (if (instance? SecretKeySpec k)
        (e/byte-array->secret-key (.getEncoded k))
        (throw (ex-info "Not a SecretKeySpec" {:alias alias}))))
    (throw (ex-info "Not a PrivateKeyEntry" {:alias alias}))))


(defn get-certificate
  "Get ^X509Certificate from keystore using given alias and password for key entry"
  ^X509Certificate
  [^KeyStore ks ^String alias]
  (if (.isCertificateEntry ks alias)
    (.getCertificate ks alias)
    (throw (ex-info "Not a CertificateEntry" {:alias alias}))))


(defn set-private-key
  "Set ^PrivateKey entry to keystore using given alias and password for key entry.
  `PBEWithHmacSHA256AndAES_256` is used to protect key entry.
  Returns nil.
  Params:
  * `certs` - vector with X509Certificate objects for this private key or chain [key-cert ca-cert], that certifies the
    corresponding public key. Should be not empty vector.
  * `password` - password is an optional parameter for key entry. May be empty String."
  [^KeyStore ks ^PrivateKey private-key ^String alias certs & {:keys [^String password] :or {password ""}}]
  (assert (seq certs) "Certificate chain cannot be empty")
  (.setEntry ks
    alias
    (KeyStore$PrivateKeyEntry. private-key (into-array X509Certificate certs))
    (KeyStore$PasswordProtection. (char-array password)
      "PBEWithHmacSHA256AndAES_256"
      (PBEParameterSpec. (s/random-bytes pbe-salt-length) pbe-iter-count))))


(defn set-secret-key
  "Set secret key to KeyStore.
  Returns nil.
  `PBEWithHmacSHA256AndAES_256` is used to protect key entry.
  Algorithm is changed from GOST3412-2015 to AES, cause GOST3412-2015 is unknown for PKCS12."
  [^KeyStore ks ^SecretKeySpec secret-key ^String alias & {:keys [^String password] :or {password ""}}]
  (.setEntry ks alias
    (KeyStore$SecretKeyEntry. (SecretKeySpec. (.getEncoded secret-key) "AES"))
    (KeyStore$PasswordProtection. (char-array password)
      "PBEWithHmacSHA256AndAES_256"
      (PBEParameterSpec. (s/random-bytes pbe-salt-length) pbe-iter-count))))


(defn set-certificate
  "Set trusted Certificate entry to keystore.
  Returns nil.
  Params:
  * `cert` - X.509 certificate."
  [^KeyStore ks ^String alias ^X509Certificate cert]
  (.setCertificateEntry ks alias cert))


(defn contains-alias?
  "Check if KeyStore contains an alias."
  [^KeyStore ks ^String alias]
  (.containsAlias ks alias))


(defn delete-entry
  "Delete entry in KeyStore using given alias.
  Returns nil."
  [^KeyStore ks ^String alias]
  (.deleteEntry ks alias))

