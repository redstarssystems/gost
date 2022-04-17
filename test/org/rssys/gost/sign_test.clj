(ns org.rssys.gost.sign-test
  (:require
    [clojure.test :as test :refer [deftest is testing]]
    [matcho.core :refer [match]]
    [org.rssys.gost.digest :as d]
    [org.rssys.gost.sign :as sut])
  (:import
    (java.security
      SecureRandom)
    (org.bouncycastle.jcajce.provider.asymmetric.ecgost12
      BCECGOST3410_2012PrivateKey
      BCECGOST3410_2012PublicKey)))


(def message "This is a message.")


(deftest gen-keypair-256-test
  (testing "GOST 3410-2012 keypair 256-bit length generated successfully"
    (let [kp          (sut/gen-keypair-256)
          public-key  (.getPublic kp)
          private-key (.getPrivate kp)
          algo-name   (.getAlgorithm public-key)
          key-length  (sut/-key-length private-key)]
      (is (instance? BCECGOST3410_2012PublicKey public-key))
      (is (instance? BCECGOST3410_2012PrivateKey private-key))
      (match algo-name "ECGOST3410-2012")
      (match key-length 256))))


(deftest gen-keypair-512-test
  (testing "GOST 3410-2012 keypair 512-bit length generated successfully"
    (let [kp          (sut/gen-keypair-512)
          public-key  (.getPublic kp)
          private-key (.getPrivate kp)
          algo-name   (.getAlgorithm public-key)
          key-length  (sut/-key-length private-key)]
      (is (instance? BCECGOST3410_2012PublicKey public-key))
      (is (instance? BCECGOST3410_2012PrivateKey private-key))
      (match algo-name "ECGOST3410-2012")
      (match key-length 512))))


(deftest sign-digest-256-test

  (testing "Signature for a wrong hash size is not allowed"
    (let [kp                  (sut/gen-keypair-256)
          private-key         (.getPrivate kp)
          wrong-length-digest (byte-array 30)]
      (is (thrown-with-msg? Error #"Digest should be 32 bytes length"
            (sut/sign-digest-256 private-key wrong-length-digest)))))

  (testing "Signature for a wrong private key size is not allowed"
    (let [kp          (sut/gen-keypair-512)
          private-key (.getPrivate kp)
          digest      (byte-array 32)]
      (is (thrown-with-msg? Error #"Private key should be 256 bit length"
            (sut/sign-digest-256 private-key digest)))))

  (testing "Signature correct size"
    (let [kp          (sut/gen-keypair-256)
          private-key (.getPrivate kp)
          digest      (d/digest-2012-256 (.getBytes message))
          signature   (sut/sign-digest-256 private-key digest)]
      (match (alength signature) 64))))


(deftest sign-digest-512-test

  (testing "Signature for a wrong hash size is not allowed"
    (let [kp                  (sut/gen-keypair-512)
          private-key         (.getPrivate kp)
          wrong-length-digest (byte-array 30)]
      (is (thrown-with-msg? Error #"Digest should be 64 bytes length"
            (sut/sign-digest-512 private-key wrong-length-digest)))))

  (testing "Signature for a wrong private key size is not allowed"
    (let [kp          (sut/gen-keypair-256)
          private-key (.getPrivate kp)
          digest      (byte-array 64)]
      (is (thrown-with-msg? Error #"Private key should be 512 bit length"
            (sut/sign-digest-512 private-key digest)))))

  (testing "Signature has correct size"
    (let [kp          (sut/gen-keypair-512)
          private-key (.getPrivate kp)
          digest      (d/digest-2012-512 (.getBytes message))
          signature   (sut/sign-digest-512 private-key digest)]
      (match (alength signature) 128))))


(deftest verify-digest-256-test

  (testing "Signature for good digest verified successfully"
    (let [kp          (sut/gen-keypair-256)
          private-key (.getPrivate kp)
          public-key  (.getPublic kp)
          digest      (d/digest-2012-256 (.getBytes message))
          signature   (sut/sign-digest-256 private-key digest)
          result      (sut/verify-digest-256 public-key digest signature)]
      (match result true)))

  (testing "Signature for bad digest verified with negative result"
    (let [kp           (sut/gen-keypair-256)
          private-key  (.getPrivate kp)
          public-key   (.getPublic kp)
          digest       (d/digest-2012-256 (.getBytes message))
          wrong-digest (byte-array (update (into [] digest) 0 inc))
          signature    (sut/sign-digest-256 private-key digest)
          bad-result   (sut/verify-digest-256 public-key wrong-digest signature)]
      (match bad-result false)))

  (testing "Signature verification for a wrong hash size is not allowed"
    (let [kp                  (sut/gen-keypair-256)
          public-key          (.getPublic kp)
          wrong-length-digest (byte-array 30)
          signature           (byte-array 64)]
      (is (thrown-with-msg? Error #"Digest should be 32 bytes length"
            (sut/verify-digest-256 public-key wrong-length-digest signature)))))

  (testing "Signature verification for a wrong public key size is not allowed"
    (let [kp         (sut/gen-keypair-512)
          public-key (.getPublic kp)
          digest     (byte-array 32)
          signature  (byte-array 64)]
      (is (thrown-with-msg? Error #"Public key should be 256 bit length"
            (sut/verify-digest-256 public-key digest signature))))))


(deftest verify-digest-512-test

  (testing "Signature for good digest verified successfully"
    (let [kp          (sut/gen-keypair-512)
          private-key (.getPrivate kp)
          public-key  (.getPublic kp)
          digest      (d/digest-2012-512 (.getBytes message))
          signature   (sut/sign-digest-512 private-key digest)
          result      (sut/verify-digest-512 public-key digest signature)]
      (match result true)))

  (testing "Signature for bad digest verified with negative result"
    (let [kp           (sut/gen-keypair-512)
          private-key  (.getPrivate kp)
          public-key   (.getPublic kp)
          digest       (d/digest-2012-512 (.getBytes message))
          wrong-digest (byte-array (update (into [] digest) 0 inc))
          signature    (sut/sign-digest-512 private-key digest)
          bad-result   (sut/verify-digest-512 public-key wrong-digest signature)]
      (match bad-result false)))

  (testing "Signature verification for a wrong hash size is not allowed"
    (let [kp                  (sut/gen-keypair-512)
          public-key          (.getPublic kp)
          wrong-length-digest (byte-array 30)
          signature           (byte-array 64)]
      (is (thrown-with-msg? Error #"Digest should be 64 bytes length"
            (sut/verify-digest-512 public-key wrong-length-digest signature)))))

  (testing "Signature verification for a wrong public key size is not allowed"
    (let [kp         (sut/gen-keypair-256)
          public-key (.getPublic kp)
          digest     (byte-array 64)
          signature  (byte-array 64)]
      (is (thrown-with-msg? Error #"Public key should be 512 bit length"
            (sut/verify-digest-512 public-key digest signature))))))


(deftest sign-256-test
  (testing "Signature for byte array has correct size"
    (let [kp          (sut/gen-keypair-256)
          private-key (.getPrivate kp)
          signature   (sut/sign-256 private-key (.getBytes message))]
      (match (alength signature) 64)))

  (testing "Signature for file has correct size"
    (let [input       "test/data/big.txt"
          kp          (sut/gen-keypair-256)
          private-key (.getPrivate kp)
          signature   (sut/sign-256 private-key input)]
      (match (alength signature) 64))))


(deftest sign-512-test

  (testing "Signature for byte array has correct size"
    (let [kp          (sut/gen-keypair-512)
          private-key (.getPrivate kp)
          signature   (sut/sign-512 private-key (.getBytes message))]
      (match (alength signature) 128)))

  (testing "Signature for file has correct size"
    (let [input       "test/data/big.txt"
          kp          (sut/gen-keypair-512)
          private-key (.getPrivate kp)
          signature   (sut/sign-512 private-key input)]
      (match (alength signature) 128))))


(deftest verify-256-test

  (testing "Signature verification for byte array is successful"
    (let [kp          (sut/gen-keypair-256)
          private-key (.getPrivate kp)
          public-key  (.getPublic kp)
          signature   (sut/sign-256 private-key (.getBytes message))
          result      (sut/verify-256 public-key (.getBytes message) signature)]
      (match result true)))

  (testing "Signature verification for a file is successful"
    (let [input       "test/data/big.txt"
          kp          (sut/gen-keypair-256)
          private-key (.getPrivate kp)
          public-key  (.getPublic kp)
          signature   (sut/sign-256 private-key input)
          result      (sut/verify-256 public-key input signature)]
      (match result true))))


(deftest verify-512-test

  (testing "Signature verification for byte array is successful"
    (let [kp          (sut/gen-keypair-512)
          private-key (.getPrivate kp)
          public-key  (.getPublic kp)
          signature   (sut/sign-512 private-key (.getBytes message))
          result      (sut/verify-512 public-key (.getBytes message) signature)]
      (match result true)))

  (testing "Signature verification for a file is successful"
    (let [input       "test/data/big.txt"
          kp          (sut/gen-keypair-512)
          private-key (.getPrivate kp)
          public-key  (.getPublic kp)
          signature   (sut/sign-512 private-key input)
          result      (sut/verify-512 public-key input signature)]
      (match result true))))


(deftest generate-shared-secret-256-test
  (testing "Generated shared secret key is generated successfully"
    (let [kp           (sut/gen-keypair-256)
          private-key  (.getPrivate kp)
          public-key   (.getPublic kp)

          kp2          (sut/gen-keypair-256)
          private-key2 (.getPrivate kp2)
          public-key2  (.getPublic kp2)

          random-iv    (byte-array 16)
          _            (.nextBytes (SecureRandom.) random-iv)

          result1      (sut/generate-shared-secret-256 private-key public-key2 random-iv)
          result2      (sut/generate-shared-secret-256 private-key2 public-key random-iv)]
      (is (= (into [] result1) (into [] result2)) "Shared keys are equal")
      (match (alength result1) 32)))

  (testing "Wrong length of public key is not allowed for generate-shared-secret-256"
    (let [kp               (sut/gen-keypair-256)
          private-key      (sut/get-private kp)

          wrong-keypair    (sut/gen-keypair-512)
          wrong-public-key (.getPublic wrong-keypair)

          random-iv        (byte-array 16)
          _                (.nextBytes (SecureRandom.) random-iv)]
      (is (thrown-with-msg? Error #"Public key should be the same length as private key"
            (sut/generate-shared-secret-256 private-key wrong-public-key random-iv)))))

  (testing "Wrong length of private key is not allowed for generate-shared-secret-256"
    (let [wrong-keypair     (sut/gen-keypair-512)
          wrong-private-key (sut/get-private wrong-keypair)

          kp2               (sut/gen-keypair-256)
          public-key2       (sut/get-public kp2)

          random-iv         (byte-array 16)
          _                 (.nextBytes (SecureRandom.) random-iv)]
      (is (thrown-with-msg? Error #"Public key should be the same length as private key"
            (sut/generate-shared-secret-256 wrong-private-key public-key2 random-iv))))))


(deftest generate-shared-secret-512-test
  (testing "Generated shared secret key is generated successfully"
    (let [kp           (sut/gen-keypair-512)
          private-key  (.getPrivate kp)
          public-key   (.getPublic kp)

          kp2          (sut/gen-keypair-512)
          private-key2 (.getPrivate kp2)
          public-key2  (.getPublic kp2)

          random-iv    (byte-array 16)
          _            (.nextBytes (SecureRandom.) random-iv)

          result1      (sut/generate-shared-secret-512 private-key public-key2 random-iv)
          result2      (sut/generate-shared-secret-512 private-key2 public-key random-iv)]
      (is (= (into [] result1) (into [] result2)) "Shared keys are equal")
      (match (alength result1) 64)))

  (testing "Wrong length of public key is not allowed for generate-shared-secret-512"
    (let [kp            (sut/gen-keypair-512)
          private-key   (.getPrivate kp)

          wrong-keypair (sut/gen-keypair-256)
          public-key2   (.getPublic wrong-keypair)

          random-iv     (byte-array 16)
          _             (.nextBytes (SecureRandom.) random-iv)]
      (is (thrown-with-msg? Error #"Public key should be 512 bit length"
            (sut/generate-shared-secret-512 private-key public-key2 random-iv)))))

  (testing "Wrong length of private key is not allowed for generate-shared-secret-512"
    (let [wrong-keypair     (sut/gen-keypair-256)
          wrong-private-key (.getPrivate wrong-keypair)

          kp2               (sut/gen-keypair-512)
          public-key2       (.getPublic kp2)

          random-iv         (byte-array 16)
          _                 (.nextBytes (SecureRandom.) random-iv)]
      (is (thrown-with-msg? Error #"Private key should be 512 bit length"
            (sut/generate-shared-secret-512 wrong-private-key public-key2 random-iv)))))

  (testing "Wrong EC Curve is not allowed"
    (let [wrong-keypair     (sut/gen-keypair-512 "Tc26-Gost-3410-12-512-paramSetC")
          wrong-private-key (.getPrivate wrong-keypair)

          kp2               (sut/gen-keypair-512)
          public-key2       (.getPublic kp2)

          random-iv         (byte-array 16)
          _                 (.nextBytes (SecureRandom.) random-iv)]
      (is (thrown-with-msg? Error #"Public key has incompatible EC Curve parameters with private key"
            (sut/generate-shared-secret-512 wrong-private-key public-key2 random-iv))))))
