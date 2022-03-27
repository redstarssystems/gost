(ns org.rssys.gost.p12store-test
  (:require
    [clojure.java.io :as io]
    [clojure.test :as test :refer [deftest is testing]]
    [matcho.core :refer [match]]
    [org.rssys.gost.cert :as cert]
    [org.rssys.gost.encrypt :as e]
    [org.rssys.gost.p12store :as sut]
    [org.rssys.gost.sign :as s])
  (:import
    (clojure.lang
      ExceptionInfo)
    (java.io
      File)
    (java.security
      KeyStore
      PrivateKey)
    (java.security.cert
      X509Certificate)
    (javax.crypto.spec
      SecretKeySpec)))


(deftest create-keystore-test

  (testing "KeyStore PKCS12 created successfully"
    (let [result (sut/create-keystore)]
      (is (instance? KeyStore result))
      (match (.getType result) "PKCS12"))))



(deftest write-keystore-test
  (testing "KeyStore PKCS12 is written successfully"
    (let [password    "Secret13"
          ks-file     (File/createTempFile "keystore" ".p12")
          _           (.deleteOnExit ks-file)
          ks-filename (.getAbsolutePath ks-file)
          ks          (sut/create-keystore)]
      (sut/write-keystore ks ks-filename password)
      (is (.exists (io/file ks-filename)) "KeyStore file is exist")
      (is (pos-int? (.length (io/file ks-filename))) "KeyStore file is not empty")
      (.delete (io/file ks-filename)))))



(deftest read-keystore-test
  (testing "KeyStore PKCS12 read successful"
    (let [password    "Secret13"
          ks-filename "test/data/ks.p12"
          ks          (sut/read-keystore ks-filename password)]
      (is (instance? KeyStore ks)))))


(deftest list-aliases-test
  (testing "KeyStore PKCS12 list successful"
    (let [password    "Secret13"
          ks-filename "test/data/ks.p12"
          ks          (sut/read-keystore ks-filename password)
          result      (sut/list-aliases ks)]
      (match result ["privatekey" "secretkey"]))))


(deftest get-private-key-test

  (testing "Read private key from KeyStore PKCS12 is successful"
    (let [password    "Secret13"
          ks-filename "test/data/ks.p12"
          ks          (sut/read-keystore ks-filename password)
          result      (sut/get-private-key ks "privatekey")]
      (is (instance? PrivateKey result))))

  (testing "Read not a private key is disallowed from KeyStore PKCS12"
    (let [password    "Secret13"
          ks-filename "test/data/ks.p12"
          ks          (sut/read-keystore ks-filename password)]
      (is (thrown-with-msg? ExceptionInfo #"Not a PrivateKey"
            (sut/get-private-key ks "secretkey"))))))


(deftest get-secret-key-test

  (testing "Read secret key from KeyStore PKCS12 is successful"
    (let [password    "Secret13"
          ks-filename "test/data/ks.p12"
          ks          (sut/read-keystore ks-filename password)
          result      (sut/get-secret-key ks "secretkey")]
      (is (instance? SecretKeySpec result))
      (match (alength (.getEncoded result)) 32)
      (match (.getAlgorithm result) "GOST3412-2015")))

  (testing "Read not a secret key is disallowed from KeyStore PKCS12"
    (let [password    "Secret13"
          ks-filename "test/data/ks.p12"
          ks          (sut/read-keystore ks-filename password)]
      (is (thrown-with-msg? ExceptionInfo #"Not a SecretKeySpec"
            (sut/get-secret-key ks "privatekey"))))))


(deftest get-certificate-test

  (testing "Read certificate entry from KeyStore PKCS12 is successful"
    (let [password    "Secret13"
          ks-filename "test/data/ks.p12"
          ks          (sut/read-keystore ks-filename password)
          result      (sut/get-certificate ks "digicert")]
      (is (instance? X509Certificate result))))

  (testing "Read not a certificate entry is disallowed from KeyStore PKCS12"
    (let [password    "Secret13"
          ks-filename "test/data/ks.p12"
          ks          (sut/read-keystore ks-filename password)]
      (is (thrown-with-msg? ExceptionInfo #"Not a CertificateEntry"
            (sut/get-certificate ks "secretkey"))))))


(deftest set-private-key-test
  (let [kp-256      (s/gen-keypair-256)
        private-256 (s/get-private kp-256)
        cert        (cert/generate-root-certificate kp-256 "cn=root-ca")
        certs-chain [cert]]

    (testing "Set private key entry cannot be done without certificate"
      (let [ks                (sut/create-keystore)
            empty-certs-chain []]
        (is (thrown-with-msg? Error #"Certificate chain cannot be empty"
              (sut/set-private-key ks private-256 "private1" empty-certs-chain)))))

    (testing "Set private key is successful"
      (let [ks    (sut/create-keystore)
            alias "private1"]
        (sut/set-private-key ks private-256 alias certs-chain)
        (is (instance? PrivateKey (sut/get-private-key ks alias)))
        (match (sut/get-private-key ks alias) private-256)))

    (testing "Set private key with password is successful"
      (let [ks       (sut/create-keystore)
            password "!Wertzxc123"
            alias    "private1"]
        (sut/set-private-key ks private-256 alias certs-chain :password password)
        (is (instance? PrivateKey (sut/get-private-key ks alias :password password)))
        (match (sut/get-private-key ks alias :password password) private-256)
        (is (thrown-with-msg? Exception #"Get Key failed"
              (sut/get-private-key ks alias :password "wrongpassword"))
          "Get key with wrong password for key entry should rise an Exception")))))


(deftest set-secret-key-test

  (testing "Set secret key key is successful"
    (let [ks         (sut/create-keystore)
          secret-key (e/generate-secret-key)
          alias      "secret1"]
      (sut/set-secret-key ks secret-key alias)
      (is (instance? SecretKeySpec (sut/get-secret-key ks alias)))))

  (testing "Set secret key with password is successful"
    (let [ks         (sut/create-keystore)
          secret-key (e/generate-secret-key)
          password   "!Wertzxc123"
          alias      "secret1"]
      (sut/set-secret-key ks secret-key alias :password password)
      (is (instance? SecretKeySpec (sut/get-secret-key ks alias :password password)))
      (match (sut/get-secret-key ks alias :password password) secret-key)
      (is (thrown-with-msg? Exception #"Get Key failed"
            (sut/get-secret-key ks alias :password "wrongpassword"))
        "Get key with wrong password for key entry should rise an Exception"))))


(deftest  set-certificate-test
  (let [ks    (sut/create-keystore)
        cert  (cert/read-cert-pem-file "test/data/c512.pem")
        alias "cert1"]
    (sut/set-certificate ks alias cert)

    (is (.containsAlias ks alias) "Alias for certificate exist in KeyStore")
    (is (instance? X509Certificate (.getCertificate ks alias)) "Entry is X509Certificate")
    (is (= cert (.getCertificate ks alias)) "Certificates are equal")))


(deftest contains-alias?-test
  (let [ks (sut/create-keystore)
        alias1 "alias1"
        alias2 "alias2"
        secret-key (e/generate-secret-key)]
    (sut/set-secret-key ks secret-key alias1)
    (is (sut/contains-alias? ks alias1) "Alias should exist")
    (is (not (sut/contains-alias? ks alias2)) "Alias should not exist")))


(deftest delete-entry-test
  (let [ks (sut/create-keystore)
        alias1 "alias1"
        alias2 "alias2"
        secret-key (e/generate-secret-key)]
    (sut/set-secret-key ks secret-key alias1)
    (sut/set-secret-key ks secret-key alias2)
    (sut/delete-entry ks alias2)
    (is (sut/contains-alias? ks alias1) "Alias should exist")
    (is (not (sut/contains-alias? ks alias2)) "Alias should not exist")))
