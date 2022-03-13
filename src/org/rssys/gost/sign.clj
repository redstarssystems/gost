(ns org.rssys.gost.sign
  "Digital signature using GOST3410-2012"
  (:require
    [clojure.java.io :as io]
    [org.rssys.gost.digest :as d])
  (:import
    (java.security
      KeyPair
      KeyPairGenerator
      PrivateKey
      PublicKey
      SecureRandom
      Security
      Signature)
    (javax.crypto
      KeyAgreement)
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


(defn get-private
  ^PrivateKey
  [^KeyPair kp]
  (.getPrivate kp))


(defn get-public
  ^PublicKey
  [^KeyPair kp]
  (.getPublic kp))


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
  (assert (= 256 (-key-length private-key)) "Private key should be 256 bit length")
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
  (assert (= 512 (-key-length private-key)) "Private key should be 512 bit length")
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
  (let [in     (io/input-stream input)
        digest (d/digest-2012-256 in :close-streams? close-streams?)]
    (when close-streams? (.close in))
    (sign-digest-256 private-key digest)))


(defn sign-512
  "Generate signature GOST3411-2012-512 for `input` using private key 512 bit length.
  Digest GOST3411-2012-512 will be calculated automatically for `input`.
  As `input` may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream.
  Returns 128 byte array with signature."
  [^BCECGOST3410_2012PrivateKey private-key input & {:keys [close-streams?] :or {close-streams? true}}]
  (let [in     (io/input-stream input)
        digest (d/digest-2012-512 in :close-streams? close-streams?)]
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
  (let [in     (io/input-stream input)
        digest (d/digest-2012-256 in :close-streams? close-streams?)]
    (when close-streams? (.close in))
    (verify-digest-256 public-key digest signature)))


(defn verify-512
  "Verify signature GOST3411-2012-512 for `input` using public key 512 bit length.
  Digest GOST3411-2012-512 will be calculated automatically for `input`.
  As `input` may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream.
  Returns true if signature is correct, false - signature is not correct."
  [^BCECGOST3410_2012PublicKey public-key input signature & {:keys [close-streams?] :or {close-streams? true}}]
  (let [in     (io/input-stream input)
        digest (d/digest-2012-512 in :close-streams? close-streams?)]
    (when close-streams? (.close in))
    (verify-digest-512 public-key digest signature)))


(defn -ec-curve
  "Returns EC Curve"
  [k]
  (.getCurve (.getParameters k)))


(defn -curve-name
  "Returns EC Curve name as String from given public key."
  ^String
  [^BCECGOST3410_2012PublicKey k]
  (:name (bean (.getParameters k))))


(defn random-bytes
  "Generate random bytes using SecureRandom.
  Returns byte array `n` bytes length with random data."
  [n]
  (let [ba-array (byte-array n)]
    (.nextBytes (SecureRandom.) ba-array)
    ba-array))


(defn generate-shared-secret-256
  "Generate shared secret key 256-bit length using Elliptic-curve Diffie–Hellman (ECDH) algorithm.
  Returns secret key bytes array of 32 bytes length.
  `my-private-key` and `other-public-key` should be 256-bit length and have the same EC Curve.
  `random-iv` is not secret and may be transferred via open channels. Recommended length is 16+ random bytes.
  The only requirement for `random-iv` be always random for any key agreement session.
  Other party should know the same `random-iv` to generate the same shared secret key."
  ^bytes
  [^BCECGOST3410_2012PrivateKey my-private-key ^BCECGOST3410_2012PublicKey other-public-key ^bytes random-iv]
  (assert (= 256 (-key-length other-public-key)) "Public key should be 256 bit length")
  (assert (= 256 (-key-length my-private-key)) "Private key should be 256 bit length")
  (assert (.equals (-ec-curve other-public-key) (-ec-curve my-private-key))
    (format "Public key has incompatible EC Curve parameters with private key: %s " (-curve-name other-public-key)))
  (let [ka       (KeyAgreement/getInstance "ECDH" "BC")
        _        (.init ka my-private-key)
        _        (.doPhase ka other-public-key true)
        key-data (.getEncoded (.generateSecret ka "GOST3412-2015"))]
    (d/hmac-2012-256 random-iv key-data)))


(defn generate-shared-secret-512
  "Generate shared secret key 512-bit length using Elliptic-curve Diffie–Hellman (ECDH) algorithm.
  Returns secret key bytes array of 64 bytes length.
  `my-private-key` and `other-public-key` should be 512-bit length and have the same EC Curve.
  `random-iv` is not secret and may be transferred via open channels. Recommended length is 32+ random bytes.
  The only requirement for `random-iv` be always random for any key agreement session.
  Other party should know the same `random-iv` to generate the same shared secret key."
  ^bytes
  [^BCECGOST3410_2012PrivateKey my-private-key ^BCECGOST3410_2012PublicKey other-public-key ^bytes random-iv]
  (assert (= 512 (-key-length other-public-key)) "Public key should be 512 bit length")
  (assert (= 512 (-key-length my-private-key)) "Private key should be 512 bit length")
  (assert (.equals (-ec-curve other-public-key) (-ec-curve my-private-key))
    (format "Public key has incompatible EC Curve parameters with private key: %s " (-curve-name other-public-key)))
  (let [ka       (KeyAgreement/getInstance "ECDH" "BC")
        _        (.init ka my-private-key)
        _        (.doPhase ka other-public-key true)
        key-data (.getEncoded (.generateSecret ka "GOST3412-2015"))]
    (d/hmac-2012-512 random-iv key-data)))


