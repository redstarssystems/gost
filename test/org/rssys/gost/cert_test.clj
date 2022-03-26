(ns org.rssys.gost.cert-test
  (:require
    [clojure.java.io :as io]
    [clojure.string :as string]
    [clojure.test :as test :refer [deftest is testing]]
    [matcho.core :refer [match]]
    [org.rssys.gost.cert :as sut]
    [org.rssys.gost.sign :as s])
  (:import
    (java.io
      File)
    (java.security.cert
      X509Certificate)
    (java.util
      Calendar)
    (org.bouncycastle.asn1
      DEROctetString)
    (org.bouncycastle.asn1.x500
      X500Name)
    (org.bouncycastle.asn1.x509
      Extension
      GeneralName
      GeneralNames
      KeyUsage)
    (org.bouncycastle.pkcs
      PKCS10CertificationRequest)))


(deftest ^:unit generate-root-certificate-test
  (let [subject "CN=root-ca"]

    (testing "Root CA certificate for keypair 256-bit length generated successfully"
      (let [keypair-256 (s/gen-keypair-256)
            result      (sut/generate-root-certificate keypair-256 subject)]
        (is (instance? X509Certificate result))
        (match (.getType result) "X.509")
        (match (.getSigAlgName result) "GOST3411-2012-256WITHECGOST3410-2012-256")))

    (testing "Root CA certificate for keypair 512-bit length generated successfully"
      (let [keypair-512 (s/gen-keypair-512)
            result      (sut/generate-root-certificate keypair-512 subject)]
        (is (instance? X509Certificate result))
        (match (.getType result) "X.509")
        (match (.getSigAlgName result) "GOST3411-2012-512WITHECGOST3410-2012-512")))

    (testing "Root CA certificate with custom parameters generated successfully"
      (let [keypair-256     (s/gen-keypair-256)
            subject'        "C=RU, O=Red Stars Systems, OU=www.rssys.org, CN=Red Stars Systems Root CA"
            calendar        (Calendar/getInstance)
            _               (.set calendar Calendar/MILLISECOND 0) ;; obfuscate millis
            not-before-date (.getTime calendar)
            serial-number   (BigInteger. (str 12345))
            not-after-date  (do (.add calendar Calendar/YEAR 3) (.getTime calendar))
            result          (sut/generate-root-certificate keypair-256 subject'
                              :not-before-date not-before-date
                              :not-after-date not-after-date
                              :serial-number serial-number)
            result-subject  (-> result .getSubjectX500Principal .getName)
            result-issuer   (-> result .getIssuerX500Principal .getName)]
        (is (instance? X509Certificate result))
        (is (= (.getSerialNumber result) serial-number))

        ;; subject and issuer in Certificate are maps, so we cannot predict correct order CN,OU,O,C in .getName
        (match result-subject #(and
                                 (string/includes? % "CN=Red Stars Systems Root CA")
                                 (string/includes? % "OU=www.rssys.org")
                                 (string/includes? % "O=Red Stars Systems")
                                 (string/includes? % "C=RU")))
        (match result-issuer #(and
                                (string/includes? % "CN=Red Stars Systems Root CA")
                                (string/includes? % "OU=www.rssys.org")
                                (string/includes? % "O=Red Stars Systems")
                                (string/includes? % "C=RU")))
        (match (.getNotBefore result) not-before-date)
        (match (.getNotAfter result) not-after-date)))))


(deftest ^:unit write-cert-der-file-test

  (testing "Write certificate in DER format"
    (let [out-cert-file     (File/createTempFile "filename" ".crt")
          _                 (.deleteOnExit out-cert-file)
          out-cert-filename (.getAbsolutePath out-cert-file)
          subject           "C=RU, O=Red Stars Systems, OU=www.rssys.org, CN=Red Stars Systems Root CA"
          keypair-256       (s/gen-keypair-256)
          cert              (sut/generate-root-certificate keypair-256 subject)
          result            (sut/write-cert-der-file cert out-cert-filename)]
      (match result out-cert-filename)
      (is (pos-int? (.length (io/file out-cert-filename))) "DER file should be not empty")
      (.delete (io/file out-cert-filename)))))


(deftest ^:unit write-cert-pem-file-test

  (testing "Write certificate in PEM format"
    (let [out-cert-file     (File/createTempFile "filename" ".pem")
          _                 (.deleteOnExit out-cert-file)
          out-cert-filename (.getAbsolutePath out-cert-file)
          subject           "C=RU, O=Red Stars Systems, OU=www.rssys.org, CN=Red Stars Systems Root CA"
          keypair-256       (s/gen-keypair-256)
          cert              (sut/generate-root-certificate keypair-256 subject)
          result            (sut/write-cert-pem-file cert out-cert-filename)]
      (match result out-cert-filename)
      (is (pos-int? (.length (io/file out-cert-filename))) "PEM file should be not empty")
      (match (slurp out-cert-filename) #(string/includes? % "BEGIN CERTIFICATE"))
      (match (slurp out-cert-filename) #(string/includes? % "END CERTIFICATE"))
      (.delete (io/file out-cert-filename)))))


(deftest ^:unit read-cert-der-file-test

  (testing "Read X.509 certificate from DER file is successful"
    (let [out-cert-file     (File/createTempFile "filename" ".crt")
          _                 (.deleteOnExit out-cert-file)
          out-cert-filename (.getAbsolutePath out-cert-file)
          subject           "C=RU, O=Red Stars Systems, OU=www.rssys.org, CN=Red Stars Systems Root CA"
          keypair-256       (s/gen-keypair-256)
          cert              (sut/generate-root-certificate keypair-256 subject)
          _                 (sut/write-cert-der-file cert out-cert-filename)
          result            (sut/read-cert-der-file out-cert-filename)]
      (match result #(instance? X509Certificate %))
      (is (= cert result) "Certificates are equal")
      (.delete (io/file out-cert-filename)))))


(deftest ^:unit read-cert-pem-file-test

  (testing "Read X.509 certificate from PEM file is successful"
    (let [out-cert-file     (File/createTempFile "filename" ".pem")
          _                 (.deleteOnExit out-cert-file)
          out-cert-filename (.getAbsolutePath out-cert-file)
          subject           "C=RU, O=Red Stars Systems, OU=www.rssys.org, CN=Red Stars Systems Root CA"
          keypair-256       (s/gen-keypair-256)
          cert              (sut/generate-root-certificate keypair-256 subject)
          _                 (sut/write-cert-pem-file cert out-cert-filename)
          result            (sut/read-cert-pem-file out-cert-filename)]
      (match result #(instance? X509Certificate %))
      (is (= cert result) "Certificates are equal")
      (.delete (io/file out-cert-filename)))))


(deftest ^:unit generate-csr-test

  (testing "Generate PKCS10 CSR is successful"
    (let [keypair (s/gen-keypair-256)
          subject "CN=webserver"
          result  (sut/generate-csr keypair subject [])]
      (is (instance? PKCS10CertificationRequest result))
      (match (.toString (.getSubject result)) subject)))

  (testing "Generate PKCS10 CSR with custom attributes is successful"
    (let [keypair    (s/gen-keypair-256)
          subject    "CN=webserver"
          extensions [(Extension. Extension/subjectAlternativeName
                        false
                        (DEROctetString. (GeneralNames. (GeneralName. (X500Name. "cn=alt-web")))))
                      (Extension. Extension/keyUsage true
                        (DEROctetString.
                          (KeyUsage. (bit-or KeyUsage/keyCertSign KeyUsage/cRLSign
                                       KeyUsage/digitalSignature))))]

          result     (sut/generate-csr keypair subject extensions)]
      (is (instance? PKCS10CertificationRequest result))
      (match (.toString (.getSubject result)) subject))))
