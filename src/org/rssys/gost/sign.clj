(ns org.rssys.gost.sign
  "Digital signature using GOST3410-2012"
  (:require
    [clojure.java.io :as io]
    [org.rssys.gost.digest :as d])
  (:import
    (java.security
      KeyPair
      KeyPairGenerator
      SecureRandom
      Security
      Signature)
    (org.bouncycastle.jcajce.provider.asymmetric.ecgost12
      BCECGOST3410_2012PrivateKey
      BCECGOST3410_2012PublicKey)
    (org.bouncycastle.jce
      ECGOST3410NamedCurveTable)
    (org.bouncycastle.jce.provider
      BouncyCastleProvider)
    (org.bouncycastle.jce.spec
      ECNamedCurveParameterSpec)))


;; helper to detect private or public key length
(defn -key-length
  [k]
  (.getFieldSize (.getYCoord (.getG (.getParameters k)))))


(defn gen-keypair-256
  "Generate 256-bit keypair for GOST3410-2012.
  Elliptic curve parameters is Tc26-Gost-3410-12-256-paramSetA.
  Returns ^KeyPair object."
  ^KeyPair []
  (Security/addProvider (BouncyCastleProvider.))
  (let [curve-params      ^ECNamedCurveParameterSpec (ECGOST3410NamedCurveTable/getParameterSpec "Tc26-Gost-3410-12-256-paramSetA")
        keypair-generator (KeyPairGenerator/getInstance "ECGOST3410-2012" "BC")
        _                 (.initialize keypair-generator curve-params (SecureRandom.))]
    (.generateKeyPair keypair-generator)))


(defn gen-keypair-512
  "Generate 512-bit keypair for GOST3410-2012.
  Elliptic curve parameters by default is Tc26-Gost-3410-12-512-paramSetA.
  Available params: Tc26-Gost-3410-12-512-paramSetA, Tc26-Gost-3410-12-512-paramSetA,
  Tc26-Gost-3410-12-512-paramSetB, Tc26-Gost-3410-12-512-paramSetC
  Returns ^KeyPair object."
  (^KeyPair [] (gen-keypair-512 "Tc26-Gost-3410-12-512-paramSetA"))
  (^KeyPair [^String ec-params]
    (Security/addProvider (BouncyCastleProvider.))
    (let [curve-params      ^ECNamedCurveParameterSpec (ECGOST3410NamedCurveTable/getParameterSpec ec-params)
          keypair-generator ^KeyPairGenerator (KeyPairGenerator/getInstance "ECGOST3410-2012" "BC")
          _                 (.initialize keypair-generator curve-params (SecureRandom.))]
      (.generateKeyPair keypair-generator))))


(defn sign-digest-256
  "Generate signature for a digest 32 bytes length using a private key 256-bit length.
  Signature algorithm is GOST3410-2012.
  Returns byte array 64 bytes length."
  ^bytes
  [^BCECGOST3410_2012PrivateKey private-key ^bytes digest-bytes]
  (Security/addProvider (BouncyCastleProvider.))
  (assert (= 32 (alength digest-bytes)) "Digest should be 32 bytes length")
  (assert (= 256 (-key-length private-key))
    "Private key should be 256 bit length")
  (let [sign-engine (Signature/getInstance "ECGOST3410-2012-256")]
    (.initSign sign-engine private-key (SecureRandom.))
    (.update sign-engine digest-bytes 0 (alength digest-bytes))
    (.sign sign-engine)))


(defn sign-digest-512
  "Generate signature for a digest 32 bytes length using a private key 512-bit length.
  Signature algorithm is GOST3410-2012.
  Returns byte array 128 bytes length."
  ^bytes
  [^BCECGOST3410_2012PrivateKey private-key ^bytes digest-bytes]
  (Security/addProvider (BouncyCastleProvider.))
  (assert (= 64 (alength digest-bytes)) "Digest should be 64 bytes length")
  (assert (= 512 (-key-length private-key))
    "Private key should be 512 bit length")
  (let [sign-engine (Signature/getInstance "ECGOST3410-2012-512")]
    (.initSign sign-engine private-key (SecureRandom.))
    (.update sign-engine digest-bytes 0 (alength digest-bytes))
    (.sign sign-engine)))


(defn sign-256
  "Generate signature GOST3411-2012-256 for `input` using private key 256 bit length.
  Digest GOST3411-2012-256 will be calculated automatically for `input`.
  As `input` may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream.
  Returns 64 byte array with signature."
  [^BCECGOST3410_2012PrivateKey private-key input & {:keys [close-streams?] :or {close-streams? true}}]
  (let [in          (io/input-stream input)
        digest      (d/digest-2012-256 in :close-streams? close-streams?)]
    (when close-streams? (.close in))
    (sign-digest-256 private-key digest)))


(defn sign-512
  "Generate signature GOST3411-2012-512 for `input` using private key 512 bit length.
  Digest GOST3411-2012-512 will be calculated automatically for `input`.
  As `input` may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream.
  Returns 128 byte array with signature."
  [^BCECGOST3410_2012PrivateKey private-key input & {:keys [close-streams?] :or {close-streams? true}}]
  (let [in          (io/input-stream input)
        digest      (d/digest-2012-512 in :close-streams? close-streams?)]
    (when close-streams? (.close in))
    (sign-digest-512 private-key digest)))


(defn verify-digest-256
  "Verify signature for digest 32 bytes length using public key 256 bit length.
  Signature algorithm is GOST3410-2012.
  Returns true if signature is correct, false - signature is not correct."
  [^BCECGOST3410_2012PublicKey public-key ^bytes digest-bytes ^bytes signature]
  (Security/addProvider (BouncyCastleProvider.))
  (assert (= 32 (alength digest-bytes)) "Digest should be 32 bytes length")
  (assert (= 256 (-key-length public-key)) "Public key should be 256 bit length")
  (let [sign-engine (Signature/getInstance "ECGOST3410-2012-256")]
    (.initVerify sign-engine public-key)
    (.update sign-engine digest-bytes 0 (alength digest-bytes))
    (.verify sign-engine signature)))


(defn verify-digest-512
  "Verify signature for digest 64 bytes length using public key 512 bit length.
  Signature algorithm is GOST3410-2012.
  Returns true if signature is correct, false - signature is not correct."
  [^BCECGOST3410_2012PublicKey public-key ^bytes digest-bytes ^bytes signature]
  (Security/addProvider (BouncyCastleProvider.))
  (assert (= 64 (alength digest-bytes)) "Digest should be 64 bytes length")
  (assert (= 512 (-key-length public-key)) "Public key should be 512 bit length")
  (let [sign-engine (Signature/getInstance "ECGOST3410-2012-512")]
    (.initVerify sign-engine public-key)
    (.update sign-engine digest-bytes 0 (alength digest-bytes))
    (.verify sign-engine signature)))


(defn verify-256
  "Verify signature GOST3411-2012-256 for `input` using public key 256 bit length.
  Digest GOST3411-2012-256 will be calculated automatically for `input`.
  As `input` may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream.
  Returns true if signature is correct, false - signature is not correct."
  [^BCECGOST3410_2012PublicKey public-key input signature & {:keys [close-streams?] :or {close-streams? true}}]
  (let [in          (io/input-stream input)
        digest      (d/digest-2012-256 in :close-streams? close-streams?)]
    (when close-streams? (.close in))
    (verify-digest-256 public-key digest signature)))


(defn verify-512
  "Verify signature GOST3411-2012-512 for `input` using public key 512 bit length.
  Digest GOST3411-2012-512 will be calculated automatically for `input`.
  As `input` may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream.
  Returns true if signature is correct, false - signature is not correct."
  [^BCECGOST3410_2012PublicKey public-key input signature & {:keys [close-streams?] :or {close-streams? true}}]
  (let [in          (io/input-stream input)
        digest      (d/digest-2012-512 in :close-streams? close-streams?)]
    (when close-streams? (.close in))
    (verify-digest-512 public-key digest signature)))


;; https://github.com/bcgit/bc-java/blob/bc3b92f1f0e78b82e2584c5fb4b226a13e7f8b3b/core/src/test/java/org/bouncycastle/crypto/test/GOST3410Test.java
