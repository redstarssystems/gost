(ns org.rssys.gost.pem
  "Utility functions to import/export keys and other stuff to PEM format"
  (:import
    (java.io
      StringReader
      StringWriter)
    (java.security
      PrivateKey
      PublicKey)
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
