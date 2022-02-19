(ns org.rssys.gost.pem-test
  (:require
    [clojure.string :as string]
    [clojure.test :refer [deftest is testing]]
    [org.rssys.gost.pem :as p]
    [org.rssys.gost.sign :as s])
  (:import
    (org.bouncycastle.jcajce.provider.asymmetric.ecgost12
      BCECGOST3410_2012PrivateKey
      BCECGOST3410_2012PublicKey)))



(deftest ^:unit private-key->pem-test

  (let [kp-256               (s/gen-keypair-256)
        private-key-256      (.getPrivate kp-256)
        public-key-256       (.getPublic kp-256)
        private-pem-256      (p/private-key->pem private-key-256)
        public-pem-256       (p/public-key->pem public-key-256)
        restored-private-256 (p/pem->private-key private-pem-256)
        restored-public-256  (p/pem->public-key public-pem-256)]

    (testing "Convert PrivateKey to PEM string is successful"
      (is (string/includes? private-pem-256 "PRIVATE")))

    (testing "Convert PublicKey to PEM string is successful"
      (is (string/includes? public-pem-256 "PUBLIC")))

    (testing "Convert PEM string to a PrivateKey is successful"
      (is (= restored-private-256 private-key-256))
      (is (instance? BCECGOST3410_2012PrivateKey restored-private-256)))

    (testing "Convert  PEM string to a PublicKey is successful"
      (is (= restored-public-256 public-key-256))
      (is (instance? BCECGOST3410_2012PublicKey restored-public-256))))

  (testing "Restored keys from PEM can sign/verify data"
    (let [private-key (p/pem->private-key (slurp "test/data/test-private-key.pem"))
          public-key  (p/pem->public-key (slurp "test/data/test-public-key.pem"))
          signature   (s/sign-512 private-key "test/data/big.txt")
          result      (s/verify-512 public-key "test/data/big.txt" signature)]
      (is result "Signature is correct"))))
