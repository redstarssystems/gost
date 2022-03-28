(ns org.rssys.gost.cert-test
  (:require
    [clojure.java.io :as io]
    [clojure.set]
    [clojure.string :as string]
    [clojure.test :refer [deftest is testing]]
    [matcho.core :refer [match]]
    [org.rssys.gost.cert :as sut]
    [org.rssys.gost.sign :as s])
  (:import
    (java.io
      ByteArrayInputStream
      File)
    (java.security.cert
      X509Certificate)
    (java.util
      Calendar)
    (org.bouncycastle.asn1
      ASN1InputStream
      DEROctetString)
    (org.bouncycastle.asn1.x500
      X500Name)
    (org.bouncycastle.asn1.x509
      AccessDescription
      CRLDistPoint
      DistributionPoint
      Extension
      Extensions
      GeneralName
      GeneralNames
      KeyUsage)
    (org.bouncycastle.jcajce.provider.asymmetric.x509
      X509CertificateObject)
    (org.bouncycastle.pkcs
      PKCS10CertificationRequest)))


(deftest generate-root-certificate-test
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


(deftest write-cert-der-file-test

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


(deftest write-cert-pem-file-test

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


(deftest read-cert-der-file-test

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


(deftest read-cert-pem-file-test

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


(deftest generate-csr-test

  (testing "Generate PKCS10 CSR is successful"
    (let [keypair (s/gen-keypair-256)
          subject "CN=webserver"
          result  (sut/generate-csr keypair subject [])]
      (is (instance? PKCS10CertificationRequest result))
      (match (.toString (.getSubject result)) subject)))

  (testing "Generate PKCS10 CSR with custom attributes is successful"
    (let [keypair    (s/gen-keypair-256)
          subject    "CN=webserver"
          extensions (conj
                       (sut/webserver-extensions ["*.rssys.org"])
                       (Extension. Extension/subjectAlternativeName
                         false
                         (DEROctetString. (GeneralNames. (GeneralName. (X500Name. "cn=alt-web")))))
                       (Extension. Extension/keyUsage true
                         (DEROctetString.
                           (KeyUsage. (bit-or KeyUsage/keyCertSign KeyUsage/cRLSign
                                        KeyUsage/digitalSignature)))))

          result     (sut/generate-csr keypair subject extensions)]
      (is (instance? PKCS10CertificationRequest result))
      (match (.toString (.getSubject result)) subject))))


(deftest extension-non-ca-test
  (testing "Extension for non CA certificates build success"
    (let [result (sut/extension-non-ca)]
      (is (instance? Extension result))
      (match (.getExtnId result) Extension/basicConstraints)
      (match (.toString (.getExtnId result)) "2.5.29.19")
      (match (.toString (.getExtnValue result)))
      (match (-> result .getParsedValue .toString) "[]")    ;; for non CA there is no TRUE
      (match (.isCritical result) true))))



(deftest extension-ca-test
  (testing "Extension for non certificates build success"
    (let [result (sut/extension-ca)]
      (is (instance? Extension result))
      (match (.getExtnId result) Extension/basicConstraints)
      (match (.toString (.getExtnId result)) "2.5.29.19")
      (match (-> result .getParsedValue .toString) "[TRUE]") ;; for CA there is TRUE value
      (match (.isCritical result) true))))


(deftest extension-alternative-names-test
  (testing "Extension for alternative names build success"
    (let [alt-name1 "www.rssys.org"
          alt-name2 "*.rssys.org"
          result    (sut/extension-alternative-names [alt-name1 alt-name2])]
      (is (instance? Extension result))
      (match (.getExtnId result) Extension/subjectAlternativeName)
      (let [s (String. (.getOctets (.getExtnValue result)))]
        (is (string/includes? s alt-name1))
        (is (string/includes? s alt-name2))))))



(deftest extension-crl-test
  (testing "Extension for CRL distribution points build success"
    (let [crl-name1 "http://localhost/crl1.pem"
          crl-name2 "http://localhost/crl2.pem"
          result    (sut/extension-crl [crl-name1 crl-name2])]
      (is (instance? Extension result))
      (match (.getExtnId result) Extension/cRLDistributionPoints)
      (let [asn1-stream   (ASN1InputStream. (ByteArrayInputStream. (.getEncoded (.getExtnValue result))))
            der-object    (.readObject asn1-stream)
            octets        (.getOctets (cast DEROctetString der-object))
            crls          (CRLDistPoint/getInstance (.readObject (ASN1InputStream. (ByteArrayInputStream. octets))))
            dist-points   (.getDistributionPoints crls)
            dist-names    (map #(.getDistributionPoint %) dist-points)
            general-names (map #(.getName %) dist-names)
            gen-name-coll (map #(.getNames %) general-names)
            crl-coll      (map #(.toString (first %)) gen-name-coll)
            s             (String. (.getOctets (.getExtnValue result)))]
        (is (some #(string/includes? % crl-name1) crl-coll))
        (is (some #(string/includes? % crl-name2) crl-coll))

        ;; and shorter variant without parsing
        (is (string/includes? s crl-name1))
        (is (string/includes? s crl-name2))))))


(deftest extension-ocsp-access-info-test
  (testing "Extension for OCSP authority access information build success"
    (let [ocsp-uri1 "http://localhost/ocsp1"
          ocsp-uri2 "http://localhost/ocsp2"
          result    (sut/extension-ocsp-access-info [ocsp-uri1 ocsp-uri2])]
      (is (instance? Extension result))
      (match (.getExtnId result) Extension/authorityInfoAccess)
      (let [s (String. (.getOctets (.getExtnValue result)))]
        (is (string/includes? s ocsp-uri1))
        (is (string/includes? s ocsp-uri2))))))


(deftest extension-key-usage-test
  (testing "KeyUsage Extension build success"
    (let [result (sut/extension-key-usage sut/typical-user-key-usage)]
      (is (instance? Extension result))
      (match (.getExtnId result) Extension/keyUsage))))


(deftest extension-extended-key-usage-test
  (testing "ExtendedKeyUsage Extension build success"
    (let [result (sut/extension-extended-key-usage sut/typical-user-extended-key-usage)]
      (is (instance? Extension result))
      (match (.getExtnId result) Extension/extendedKeyUsage))))


(deftest e-coll->extensions-test
  (testing "Extensions object build success"
    (let [result (sut/e-coll->extensions
                   [(sut/extension-non-ca)
                    (sut/extension-extended-key-usage sut/typical-user-extended-key-usage)
                    (sut/extension-key-usage sut/typical-user-key-usage)])]
      (is (instance? Extensions result)))))


(deftest ca-extensions-test
  (let [result (sut/ca-extensions)]
    (is (every? #(instance? Extension %) result) "Every item is Extension")))



(deftest webserver-extensions-test
  (let [result (sut/webserver-extensions ["*.rssys.org"])]
    (is (every? #(instance? Extension %) result) "Every item is Extension")))


(deftest user-extensions-test
  (let [result (sut/user-extensions)]
    (is (every? #(instance? Extension %) result) "Every item is Extension")))


(deftest csr->pem-string-test
  (let [keypair (s/gen-keypair-256)
        subject "CN=webserver"
        csr     (sut/generate-csr keypair subject (sut/webserver-extensions ["www.rssys.org"]))
        result  (sut/csr->pem-string csr)]
    (is (string? result))
    (is (string/includes? result "BEGIN CERTIFICATE REQUEST"))
    (is (string/includes? result "END CERTIFICATE REQUEST"))))


(deftest pem-string->csr-test
  (let [csr-pem (slurp "test/data/user.csr")
        result  (sut/pem-string->csr csr-pem)]
    (is (instance? PKCS10CertificationRequest result))))


(deftest get-cert-extensions-test
  (let [cert   (sut/read-cert-der-file "test/data/user.crt")
        result (sut/get-cert-extensions cert)]
    (is (every? #(instance? Extension %) result) "Every item is Extension")))


(deftest get-cert-crl-test
  (let [cert   (sut/read-cert-der-file "test/data/user.crt")
        result (sut/get-cert-crl cert)]
    (is (every? #(instance? DistributionPoint %) result) "Every item is DistributionPoint")))


(deftest get-cert-authority-access-info-test
  (let [cert   (sut/read-cert-der-file "test/data/user.crt")
        result (sut/get-cert-authority-access-info cert)]
    (is (every? #(instance? AccessDescription %) result) "Every item is AccessDescription")))


(deftest generate-certificate-test
  (let [root-ca-keypair          (s/gen-keypair-256)
        root-ca-subject          "CN=Red Stars Systems Root CA,OU=www.rssys.org,O=Red Stars Systems,C=RU"
        root-ca-cert             (sut/generate-root-certificate root-ca-keypair root-ca-subject)
        webserver-keypair        (s/gen-keypair-256)
        webserver-subject        "CN=www.rssys.org"
        webserver-csr            (sut/generate-csr webserver-keypair webserver-subject
                                   (sut/webserver-extensions ["www.rssys.org"]))
        webserver-not-after-date (.getTime (doto (Calendar/getInstance) (.add Calendar/YEAR 2)))
        webserver-cert1          (sut/generate-certificate root-ca-cert root-ca-keypair webserver-csr)
        custom-serial            (BigInteger. (str 123456789))
        webserver-cert2          (sut/generate-certificate root-ca-cert root-ca-keypair webserver-csr
                                   {:not-after-date   webserver-not-after-date
                                    :serial-number    custom-serial
                                    :merge-extensions (sut/e-coll->extensions
                                                        [(sut/extension-crl ["https://ca.rssys.org/crl.pem"])
                                                         (sut/extension-ocsp-access-info ["https://ca.rssys.org/ocsp"])])})
        webserver-cert3          (sut/generate-certificate root-ca-cert root-ca-keypair webserver-csr
                                   {:not-after-date      webserver-not-after-date
                                    :override-extensions (sut/e-coll->extensions
                                                           (sut/webserver-extensions ["www.rssys.org"]))
                                    :merge-extensions    (sut/e-coll->extensions
                                                           [(sut/extension-crl ["https://ca.rssys.org/crl.pem"])
                                                            (sut/extension-ocsp-access-info ["https://ca.rssys.org/ocsp"])])})
        user-keypair             (s/gen-keypair-256)
        user-subject             "CN=Tony Stark,OU=Investigations,O=Red Stars Systems,C=RU"

        calendar1                (Calendar/getInstance)
        _                        (.set calendar1 Calendar/MILLISECOND 0) ;; obfuscate millis
        user-not-before-date     (.getTime (doto calendar1 (.add Calendar/DATE -1)))

        calendar2                (Calendar/getInstance)
        _                        (.set calendar2 Calendar/MILLISECOND 0) ;; obfuscate millis
        user-not-after-date      (.getTime (doto calendar2 (.add Calendar/YEAR 2)))

        user-csr                 (sut/generate-csr user-keypair user-subject (sut/user-extensions))
        user-cert1               (sut/generate-certificate root-ca-cert root-ca-keypair user-csr)
        user-cert2               (sut/generate-certificate root-ca-cert root-ca-keypair user-csr
                                   {:not-before-date  user-not-before-date
                                    :not-after-date   user-not-after-date
                                    :merge-extensions (sut/e-coll->extensions
                                                        [(sut/extension-crl ["https://ca.rssys.org/crl.pem"])
                                                         (sut/extension-ocsp-access-info ["https://ca.rssys.org/ocsp"])])})
        user-cert3               (sut/generate-certificate root-ca-cert root-ca-keypair user-csr
                                   {:not-after-date      user-not-after-date
                                    :override-extensions (sut/e-coll->extensions
                                                           (conj
                                                             (sut/user-extensions)
                                                             (sut/extension-crl ["https://ca.rssys.org/crl.pem"])
                                                             (sut/extension-ocsp-access-info ["https://ca.rssys.org/ocsp"])))})]
    (is (instance? X509CertificateObject webserver-cert1))
    (is (instance? X509CertificateObject webserver-cert2))
    (is (instance? X509CertificateObject webserver-cert3))
    (is (instance? X509CertificateObject user-cert1))
    (is (instance? X509CertificateObject user-cert2))
    (is (instance? X509CertificateObject user-cert3))

    (testing "CSR extensions are present in certificate"

      (testing "Web server CSR"
        (let [csr-extensions-object (.getRequestedExtensions webserver-csr)
              csr-ext-coll          (sut/extensions->e-coll csr-extensions-object)
              cert-ext              (sut/get-cert-extensions webserver-cert1)
              ext-values-set-fn     (fn [e-coll] (into #{} (map #(.toString (.getExtnValue %)) e-coll)))]
          (is (clojure.set/subset?
                (ext-values-set-fn csr-ext-coll)
                (ext-values-set-fn cert-ext)))))

      (testing "User CSR"
        (let [csr-extensions-object (.getRequestedExtensions user-csr)
              csr-ext-coll          (sut/extensions->e-coll csr-extensions-object)
              cert-ext              (sut/get-cert-extensions user-cert1)
              ext-values-set-fn     (fn [e-coll] (into #{} (map #(.toString (.getExtnValue %)) e-coll)))]
          (is (clojure.set/subset?
                (ext-values-set-fn csr-ext-coll)
                (ext-values-set-fn cert-ext))))))

    (testing "Override extensions replace CSR extensions"
      (let [user-ext-coll         (sut/user-extensions)
            ext-values-set-fn     (fn [e-coll] (into #{} (map #(.toString (.getExtnValue %)) e-coll)))
            cert                  (sut/generate-certificate root-ca-cert root-ca-keypair webserver-csr
                                    {:not-after-date      webserver-not-after-date
                                     :override-extensions (sut/e-coll->extensions
                                                            user-ext-coll)})
            csr-extensions-object (.getRequestedExtensions webserver-csr)
            csr-ext-coll          (sut/extensions->e-coll csr-extensions-object)
            cert-ext              (sut/get-cert-extensions cert)]

        (is (not (clojure.set/subset?
                   (ext-values-set-fn csr-ext-coll)
                   (ext-values-set-fn cert-ext))) "CSR extensions not present in certificate")

        (is (clojure.set/subset?
              (ext-values-set-fn user-ext-coll)
              (ext-values-set-fn cert-ext)) "Overridden extensions present in certificate")))

    (testing "Merge + CSR extensions are present in certificate"
      (let [merge-ext-coll        [(sut/extension-crl ["https://ca.rssys.org/crl.pem"])
                                   (sut/extension-ocsp-access-info ["https://ca.rssys.org/ocsp"])]
            ext-values-set-fn     (fn [e-coll] (into #{} (map #(.toString (.getExtnValue %)) e-coll)))
            cert                  (sut/generate-certificate root-ca-cert root-ca-keypair webserver-csr
                                    {:not-after-date   webserver-not-after-date
                                     :merge-extensions (sut/e-coll->extensions
                                                         merge-ext-coll)})
            csr-extensions-object (.getRequestedExtensions webserver-csr)
            csr-ext-coll          (sut/extensions->e-coll csr-extensions-object)
            cert-ext              (sut/get-cert-extensions cert)]

        (is (clojure.set/subset?
              (ext-values-set-fn csr-ext-coll)
              (ext-values-set-fn cert-ext)) "CSR extensions present in certificate")

        (is (clojure.set/subset?
              (ext-values-set-fn merge-ext-coll)
              (ext-values-set-fn cert-ext)) "Merge extensions present in certificate")))

    (testing "Merge + overridden extensions are present in certificate"
      (let [user-ext-coll         (sut/user-extensions)
            merge-ext-coll        [(sut/extension-crl ["https://ca.rssys.org/crl.pem"])
                                   (sut/extension-ocsp-access-info ["https://ca.rssys.org/ocsp"])]
            ext-values-set-fn     (fn [e-coll] (into #{} (map #(.toString (.getExtnValue %)) e-coll)))
            cert                  (sut/generate-certificate root-ca-cert root-ca-keypair webserver-csr
                                    {:not-after-date      webserver-not-after-date
                                     :override-extensions (sut/e-coll->extensions
                                                            user-ext-coll)
                                     :merge-extensions    (sut/e-coll->extensions
                                                            merge-ext-coll)})
            csr-extensions-object (.getRequestedExtensions webserver-csr)
            csr-ext-coll          (sut/extensions->e-coll csr-extensions-object)
            cert-ext              (sut/get-cert-extensions cert)]

        (is (not (clojure.set/subset?
                   (ext-values-set-fn csr-ext-coll)
                   (ext-values-set-fn cert-ext))) "CSR extensions not present in certificate")

        (is (clojure.set/subset?
              (ext-values-set-fn user-ext-coll)
              (ext-values-set-fn cert-ext)) "Overridden extensions present in certificate")

        (is (clojure.set/subset?
              (ext-values-set-fn merge-ext-coll)
              (ext-values-set-fn cert-ext)) "Merge extensions present in certificate")))

    (testing "Not before date and not after date are present in certificate"
      (let [cert-not-before-date (.getNotBefore user-cert2)
            cert-not-after-date  (.getNotAfter user-cert2)]
        (is (= user-not-before-date cert-not-before-date))
        (is (= user-not-after-date cert-not-after-date))))

    (testing "Subject present in certificate"
      (let [cert-subject (.toString (.getSubjectDN user-cert2))]
        (is (= user-subject cert-subject))))

    (testing "Serial number generated automatically"
      (let [cert-serial (.getSerialNumber user-cert2)]
        (is (> (count (str cert-serial)) 0))
        (is (pos? cert-serial))))

    (testing "Custom serial number is present in certificate"
      (let [custom-cert-serial (.getSerialNumber webserver-cert2)]
        (is (= custom-cert-serial custom-serial))))))
