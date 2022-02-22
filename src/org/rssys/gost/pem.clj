(ns org.rssys.gost.pem
  "Utility functions to import/export keys and other stuff to PEM format"
  (:require
    [clojure.string :as string])
  (:import
    (java.io
      StringReader
      StringWriter)
    (java.security
      PrivateKey
      PublicKey)
    (javax.crypto
      Cipher
      SecretKeyFactory)
    (javax.crypto.spec
      IvParameterSpec
      PBEKeySpec
      SecretKeySpec)
    (org.bouncycastle.asn1.nist
      NISTObjectIdentifiers)
    (org.bouncycastle.asn1.pkcs
      PrivateKeyInfo)
    (org.bouncycastle.openssl
      PEMEncryptedKeyPair
      PEMParser)
    (org.bouncycastle.openssl.jcajce
      JcaPEMKeyConverter
      JcaPEMWriter
      JceOpenSSLPKCS8DecryptorProviderBuilder
      JcePEMDecryptorProviderBuilder)
    (org.bouncycastle.pkcs
      PKCS8EncryptedPrivateKeyInfo)
    (org.bouncycastle.pkcs.jcajce
      JcaPKCS8EncryptedPrivateKeyInfoBuilder
      JcePKCSPBEOutputEncryptorBuilder)
    (org.bouncycastle.util.io.pem
      PemObject
      PemReader)))


(defn private-key->pem
  "Convert ECGOST3410-2012 private key to PEM (PKCS#8) string.
  Private key is unencrypted!"
  ^String
  [^PrivateKey private-key]
  (let [sw         (StringWriter.)
        pem-writer (JcaPEMWriter. sw)]
    (.writeObject pem-writer private-key)
    (.close pem-writer)
    (.toString sw)))


(defn public-key->pem
  "Convert ECGOST3410-2012 public key to PEM public key string"
  ^String
  [^PublicKey public-key]
  (let [sw         (StringWriter.)
        pem-writer (JcaPEMWriter. sw)]
    (.writeObject pem-writer public-key)
    (.close pem-writer)
    (.toString sw)))


(defn pem->private-key
  "Convert PEM (PKCS#8) string to a private key ECGOST3410-2012.
  PEM private key is unencrypted!"
  ^PrivateKey
  [^String pem-key]
  (let [pem-parser  (PEMParser. (StringReader. pem-key))
        pem-keypair ^PrivateKeyInfo (.readObject pem-parser)
        converter   (doto (JcaPEMKeyConverter.) (.setProvider "BC"))]
    (.getPrivateKey converter pem-keypair)))


(defn pem->public-key
  "Convert PEM public key string to a public key ECGOST3410-2012"
  ^PublicKey
  [^String pem-key]
  (let [sr          (StringReader. pem-key)
        pem-parser  (PEMParser. sr)
        pem-keypair (.readObject pem-parser)
        converter   (doto (JcaPEMKeyConverter.) (.setProvider "BC"))]
    (.getPublicKey converter pem-keypair)))


(defn private-key->encrypted-pem
  "Convert ECGOST3410-2012 private key to encrypted PEM (PKCS#8) string.
  Private key will be encrypted with `password` using AES256-CBC."
  ^String
  [^PrivateKey private-key ^String password]
  (let [sw           (StringWriter.)
        pw           (JcaPEMWriter. sw)
        ebuilder     (->
                       (JcePKCSPBEOutputEncryptorBuilder. NISTObjectIdentifiers/id_aes256_CBC)
                       (.setProvider "BC")
                       (.build (char-array password)))
        pkcs8Builder (.build (JcaPKCS8EncryptedPrivateKeyInfoBuilder. private-key) ebuilder)]
    (.writeObject pw pkcs8Builder)
    (.close pw)
    (.toString sw)))


(defn encrypted-pem->private-key
  "Convert encrypted PEM (PKCS#8) string to ECGOST3410-2012 private key.
  PEM will be decrypted with `password`."
  ^PrivateKey
  [^String private-key-pem ^String password]
  (let [pem-parser  (PEMParser. (StringReader. private-key-pem))
        pem-keypair ^PrivateKeyInfo (.readObject pem-parser)
        converter   (doto (JcaPEMKeyConverter.) (.setProvider "BC"))
        private-key (cond

                      (instance? PKCS8EncryptedPrivateKeyInfo pem-keypair)
                      (->> (.decryptPrivateKeyInfo ^PKCS8EncryptedPrivateKeyInfo pem-keypair
                             (.build (JceOpenSSLPKCS8DecryptorProviderBuilder.) (char-array password)))
                        (.getPrivateKey converter))

                      (instance? PEMEncryptedKeyPair pem-keypair)
                      (->> (.decryptKeyPair ^PEMEncryptedKeyPair pem-keypair
                             (.build (JcePEMDecryptorProviderBuilder.) (char-array password)))
                        (.getKeyPair converter)
                        (.getPrivate))

                      :else
                      (throw (ex-info "Unknown PEM type" {:type (type pem-keypair)})))]

    private-key))


(defn write-bytes-to-pem
  "Writes arbitrary byte array to PEM string.
  * `type` - type of `data` which will be in header, before and after PEM content.
    Example of `type`: SIGNATURE, HMAC etc.
  * `data` - any byte array"
  ^String
  [^String type ^bytes data]
  (let [pem-obj    (PemObject. type data)
        sw         (StringWriter.)
        pem-writer (JcaPEMWriter. sw)]
    (.writeObject pem-writer pem-obj)
    (.close pem-writer)
    (.toString sw)))


(defn read-bytes-from-pem
  "Reads arbitrary byte array from PEM string.
  Returns byte array."
  ^bytes
  [^String pem-data]
  (let [sr         (StringReader. pem-data)
        pem-reader (PemReader. sr)
        data       (.readPemObject pem-reader)]
    (.close sr)
    (.close pem-reader)
    (.getContent data)))


(defn secret-key->pem
  "Convert secret key to PEM (PKCS#8) string.
  Secret key is unencrypted!"
  ^String
  [^SecretKeySpec secret-key]
  (write-bytes-to-pem "SECRET KEY" (.getEncoded secret-key)))


(defn pem->secret-key
  "Convert plain PEM (PKCS#8) string to SecretKey.
  * `algo-name` - allowed values \"GOST28147\" or \"GOST3412-2015\" (default)"
  ([^String pem-secret-key]
    (pem->secret-key pem-secret-key "GOST3412-2015"))
  ([^String pem-secret-key ^String algo-name]
    (assert (string/includes? pem-secret-key "SECRET KEY") "PEM string should contain secret key.")
    (SecretKeySpec. (read-bytes-from-pem pem-secret-key) algo-name)))


(def ^:const pem-iv-16 [2 0 2 2 0 1 0 1 1 0 1 0 2 2 0 2])   ;; mirrored date 20220101 | 10102202
(def ^:const pem-salt-string "org.rssys.password.salt.string!!")


(defn- init-pem-cipher
  [^String password ^bytes salt ^long mode ^bytes iv-16]
  (let [secret-factory (SecretKeyFactory/getInstance "PBKDF2WITHHMACGOST3411" "BC")
        key-spec       (PBEKeySpec. (.toCharArray password) salt 1024 256)
        new-secret-key (SecretKeySpec. (.getEncoded (.generateSecret secret-factory key-spec)) "GOST3412-2015")
        cipher         (Cipher/getInstance "GOST3412-2015/CBC/PKCS7Padding")
        _              (.init cipher mode new-secret-key (IvParameterSpec. iv-16))]
    cipher))


(defn secret-key->encrypted-pem
  "Convert secret key to encrypted PEM (PKCS#8) string.
  Secret key will be encrypted with key derived from PBKDF2(`password`) using GOST3412-2015-CBC"
  ^String
  [^SecretKeySpec secret-key ^String password]
  (write-bytes-to-pem "ENCRYPTED SECRET KEY"
    (let [data-to-be-encrypted (.getEncoded secret-key)
          cipher               (init-pem-cipher password (.getBytes pem-salt-string) Cipher/ENCRYPT_MODE (byte-array pem-iv-16))]
      (.doFinal cipher data-to-be-encrypted))))


(defn encrypted-pem->secret-key
  "Convert encrypted PEM (PKCS#8) string to SecretKey.
  * `algo-name` - allowed values \"GOST28147\" or \"GOST3412-2015\" (default)"
  ([^String encrypted-pem-secret-key ^String password]
    (encrypted-pem->secret-key encrypted-pem-secret-key password "GOST3412-2015"))
  ([^String encrypted-pem-secret-key ^String password ^String algo-name]
    (assert (string/includes? encrypted-pem-secret-key "ENCRYPTED SECRET KEY") "PEM string should contain encrypted secret key.")
    (SecretKeySpec.
      (let [encrypted-bytes (read-bytes-from-pem encrypted-pem-secret-key)
            cipher               (init-pem-cipher password (.getBytes pem-salt-string) Cipher/DECRYPT_MODE (byte-array pem-iv-16))]
        (.doFinal cipher encrypted-bytes))
      algo-name)))
