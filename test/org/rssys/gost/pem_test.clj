(ns org.rssys.gost.pem-test
  (:require
    [clojure.string :as string]
    [clojure.test :refer [deftest is testing]]
    [matcho.core :refer [match]]
    [org.rssys.gost.encrypt :as e]
    [org.rssys.gost.pem :as p]
    [org.rssys.gost.sign :as s])
  (:import
    (javax.crypto.spec
      SecretKeySpec)
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


(deftest ^:unit private-key->encrypted-pem-test
  (testing "Convert private key to encrypted PEM is successful"
    (let [password    "123456"
          private-key (p/pem->private-key (slurp "test/data/test-private-key.pem"))
          pem-string  (p/private-key->encrypted-pem private-key password)]
      (is (string/includes? pem-string "ENCRYPTED PRIVATE")))))


(deftest ^:unit encrypted-pem->private-key-test

  (testing "Open encrypted PEM file with private key is successful"
    (let [input-file  "test/data/test-encrypted-private-key.pem"
          password    "123456"
          private-key (p/encrypted-pem->private-key (slurp input-file) password)]
      (is (instance? BCECGOST3410_2012PrivateKey private-key)))))


(deftest ^:unit write-bytes-to-pem-test
  (testing "Converting byte array to PEM string is successful"
    (let [data       (.getBytes "Hello, world!")
          data-type  "PLAIN TEXT"
          pem-result (p/write-bytes-to-pem data-type data)]
      (is (string/includes? pem-result data-type)))))


(deftest ^:unit write-struct-to-pem-test
  (testing "Writing structured data to PEM string is successful"
    (let [data           (.getBytes "Hello")
          headers        {:status "unencrypted" :date "01-01-2022"}
          data-type      "MESSAGE"
          pem-result     (p/write-struct-to-pem {:data data :type data-type :headers headers})
          correct-result (slurp "test/data/test-plain-with-headers.pem")]
      (is (string/starts-with? pem-result correct-result)))))


(deftest ^:unit read-struct-from-pem-test
  (testing "Reading structured data from PEM string is successful"
    (let [data      (into [] (.getBytes "Hello"))
          headers   {"status" "unencrypted" "date" "01-01-2022"}
          data-type "MESSAGE"
          input-pem (slurp "test/data/test-plain-with-headers.pem")
          result    (p/read-struct-from-pem input-pem)]
      (match (:type result) data-type)
      (match (:headers result) headers)
      (match (into [] (:data result)) data))))


(deftest ^:unit read-bytes-from-pem-test
  (testing "Converting PEM string to byte array is successful"
    (let [data   "-----BEGIN PLAIN TEXT-----\nSGVsbG8sIHdvcmxkIQ==\n-----END PLAIN TEXT-----"
          result (p/read-bytes-from-pem data)]
      (match (String. result) "Hello, world!"))))


(deftest ^:unit secret-key->pem-test
  (testing "Converting SecretKeySpec to PEM string is successful"
    (let [secret-key (e/generate-secret-key)
          pem-result (p/secret-key->pem secret-key)]
      (is (string/includes? pem-result "SECRET KEY")))))


(deftest ^:unit pem->secret-key-test
  (testing "Converting PEM string to SecretKeySpec is successful"
    (let [data   "-----BEGIN SECRET KEY-----\nHVyE+5SDlYxLhzF5dZ0abz/zr+oeGsdi2qZcOVc4ZOI=\n-----END SECRET KEY-----\n"
          result (p/pem->secret-key data)]
      (is (instance? SecretKeySpec result))
      (match (alength (.getEncoded result)) 32))))


(deftest ^:unit secret-key->encrypted-pem-test
  (testing "Converting SecretKeySpec to encrypted PEM string is successful"
    (let [secret-key (e/generate-secret-key)
          pem-result (p/secret-key->encrypted-pem secret-key "123456")]
      (is (string/includes? pem-result "ENCRYPTED SECRET KEY")))))


(deftest ^:unit encrypted-pem->secret-key-test
  (testing "Converting encrypted PEM string to SecretKeySpec is successful"
    (let [data          (slurp "test/data/test-secret-key.pem")
          bad-password  "1234567"
          good-password "123456"
          result        (p/encrypted-pem->secret-key data good-password)]
      (is (instance? SecretKeySpec result))
      (match (alength (.getEncoded result)) 32)
      (is (thrown-with-msg? Exception #"pad block corrupted"
            (p/encrypted-pem->secret-key data bad-password))))))
