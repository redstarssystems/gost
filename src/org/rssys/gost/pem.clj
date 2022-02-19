(ns org.rssys.gost.pem
  "Utility functions to import/export keys to PEM format"
  (:import
    (java.io
      StringReader
      StringWriter)
    (java.security
      KeyFactory
      PrivateKey
      PublicKey)
    (java.security.spec
      PKCS8EncodedKeySpec)
    (org.bouncycastle.asn1.pkcs
      PrivateKeyInfo)
    (org.bouncycastle.openssl
      PEMParser)
    (org.bouncycastle.openssl.jcajce
      JcaPEMKeyConverter
      JcaPEMWriter)))


(defn private-key->pem
  "Convert ECGOST3410-2012 private key to PEM private key string.
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
  "Convert PEM private key string to a private key ECGOST3410-2012.
  PEM private key is unencrypted!"
  ^PrivateKey
  [^String pem-key]
  (let [pem-parser  (PEMParser. (StringReader. pem-key))
        pem-keypair ^PrivateKeyInfo (.readObject pem-parser)
        ek          (PKCS8EncodedKeySpec. (.getEncoded pem-keypair))
        kf          (KeyFactory/getInstance "ECGOST3410-2012" "BC")]
    (.generatePrivate kf ek)))


(defn pem->public-key
  "Convert PEM public key string to a public key ECGOST3410-2012"
  ^PublicKey
  [^String pem-key]
  (let [sr          (StringReader. pem-key)
        pem-parser  (PEMParser. sr)
        pem-keypair  (.readObject pem-parser)
        converter (doto (JcaPEMKeyConverter.) (.setProvider "BC"))]
    (.getPublicKey converter pem-keypair)))

