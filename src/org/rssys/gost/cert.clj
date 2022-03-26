(ns org.rssys.gost.cert
  "X.509 certificates functions"
  (:require
    [clojure.java.io :as io]
    [org.rssys.gost.pem :as pem]
    [org.rssys.gost.sign :as s])
  (:import
    (java.security
      KeyPair
      Security)
    (java.util
      Calendar
      Date)
    (org.bouncycastle.asn1
      DEROctetString)
    (org.bouncycastle.asn1.pkcs
      PKCSObjectIdentifiers)
    (org.bouncycastle.asn1.x500
      X500Name)
    (org.bouncycastle.asn1.x509
      BasicConstraints
      CRLDistPoint
      DistributionPoint
      DistributionPointName
      ExtendedKeyUsage
      Extension
      Extensions
      GeneralName
      GeneralNames
      KeyPurposeId
      KeyUsage)
    (org.bouncycastle.cert.jcajce
      JcaX509CertificateConverter
      JcaX509ExtensionUtils
      JcaX509v3CertificateBuilder)
    (org.bouncycastle.jcajce.provider.asymmetric.x509
      CertificateFactory
      X509CertificateObject)
    (org.bouncycastle.jce.provider
      BouncyCastleProvider)
    (org.bouncycastle.operator.jcajce
      JcaContentSignerBuilder)
    (org.bouncycastle.pkcs
      PKCS10CertificationRequest)
    (org.bouncycastle.pkcs.jcajce
      JcaPKCS10CertificationRequestBuilder)))


;;;;;;;;;;
;; KeyUsage flags
;;;;;;;;;;
;; See https://access.redhat.com/documentation/en-us/red_hat_certificate_system/9/html/administration_guide/standard_x.509_v3_certificate_extensions#Discussion-PKIX_Extended_Key_Usage_Extension_Uses

;; digitalSignature (0) for SSL client certificates, S/MIME signing certificates, and object-signing certificates.
;; nonRepudiation (1) for some S/MIME signing certificates and object-signing certificates. (Use of this bit is controversial. )
;; keyEncipherment (2) for SSL server certificates and S/MIME encryption certificates.
;; dataEncipherment (3) when the subject's public key is used to encrypt user data instead of key material.
;; keyAgreement (4) when the subject's public key is used for key agreement.
;; keyCertSign (5) for all CA signing certificates.
;; cRLSign (6) for CA signing certificates that are used to sign CRLs.
;; encipherOnly (7) if the public key is used only for enciphering data. If this bit is set, keyAgreement should also be set.
;; decipherOnly (8) if the public key is used only for deciphering data. If this bit is set, keyAgreement should also be set.

(def typical-ca-key-usage
  "Returns ^KeyUsage objects for typical CA key usage."
  [KeyUsage/keyCertSign KeyUsage/cRLSign KeyUsage/digitalSignature])


(def typical-user-key-usage
  "Returns ^KeyUsage objects for typical user certificate."
  [KeyUsage/digitalSignature KeyUsage/keyEncipherment KeyUsage/dataEncipherment KeyUsage/keyAgreement])


(def typical-web-server-key-usage
  "Returns ^KeyUsage objects for typical web server certificate."
  [KeyUsage/digitalSignature KeyUsage/keyEncipherment KeyUsage/keyAgreement])


;;;;;;;;;;
;; ExtendedKeyUsage flags
;;;;;;;;;;

(def typical-user-extended-key-usage
  "Returns ^KeyPurposeId objects for typical user certificate."
  [KeyPurposeId/id_kp_clientAuth KeyPurposeId/id_kp_emailProtection KeyPurposeId/id_kp_codeSigning])


(def typical-web-server-extended-key-usage
  "Returns ^KeyPurposeId objects for typical web server certificate."
  [KeyPurposeId/id_kp_clientAuth KeyPurposeId/id_kp_serverAuth])


;;;;;;;;;;
;; Extensions for certificates (ASN1 objects)
;;;;;;;;;;

(defn extension-non-ca
  "Returns ^Extension extension which indicates that certificate is a not CA certificate"
  ^Extension
  []
  (Extension. Extension/basicConstraints true (DEROctetString. (BasicConstraints. false))))


(defn extension-ca
  "Returns ^Extension extension which indicates whether a certificate is a CA certificate."
  ^Extension
  []
  (Extension. Extension/basicConstraints true (DEROctetString. (BasicConstraints. true))))


(defn extension-alternative-names
  "Returns ^Extension for alternative names (e.g. server domain names: [\"rssys.org\"])."
  ^Extension
  [alt-names]
  (let [gen-names (map #(GeneralName. GeneralName/dNSName ^String %) alt-names)]
    (Extension. Extension/subjectAlternativeName
      false
      (DEROctetString. ^GeneralNames (GeneralNames.
                                       ^"[Lorg.bouncycastle.asn1.x509.GeneralName;"
                                       (into-array GeneralName gen-names))))))


(defn extension-crl
  "Returns ^Extension for CRL distribution points (e.g. [http://localhost/crl.pem])."
  ^Extension
  [crl-strings]
  (let [crl-dist-points (map #(DistributionPoint.
                                (DistributionPointName.
                                  DistributionPointName/FULL_NAME
                                  (GeneralNames. (GeneralName. GeneralName/uniformResourceIdentifier ^String %)))
                                nil nil)
                          crl-strings)]
    (Extension. Extension/cRLDistributionPoints
      false
      (.getEncoded
        (CRLDistPoint.
          (into-array DistributionPoint
            crl-dist-points))))))



(defn extension-key-usage
  "Returns ^Extension for key usage according to flags.
   Flags is a collection of ^KeyUsage objects. E.g [KeyUsage/digitalSignature KeyUsage/keyCertSign] "
  [key-usage-flags]
  (Extension. Extension/keyUsage
    true
    (DEROctetString.
      (KeyUsage. (apply bit-or key-usage-flags)))))


(defn extension-extended-key-usage
  "Returns ^Extension for extended key usage according to flags.
  Flags is a collection of ^KeyPurposeId objects. E.g. [KeyPurposeId/id_kp_serverAuth KeyPurposeId/id_kp_clientAuth]"
  [flags]
  (assert (every? #(instance? KeyPurposeId %) flags) "Flags should contain ^KeyPurposeId objects only.")
  (Extension. Extension/extendedKeyUsage
    true
    (DEROctetString. ^ExtendedKeyUsage (ExtendedKeyUsage.
                                         ^"[Lorg.bouncycastle.asn1.x509.KeyPurposeId;"
                                         (into-array KeyPurposeId flags)))))


(defn e-coll->extensions
  "Convert collection of ^Extension objects to ^Extensions object "
  ^Extensions
  [e-coll]
  (Extensions. ^"[Lorg.bouncycastle.asn1.x509.Extension;" (into-array Extension e-coll)))


(defn ca-extensions
  []
  [(extension-ca)
   (extension-key-usage typical-ca-key-usage)])


(defn webserver-extensions
  [alternative-names]
  [(extension-non-ca)
   (extension-key-usage typical-web-server-key-usage)
   (extension-extended-key-usage typical-web-server-extended-key-usage)
   (extension-alternative-names alternative-names)])


(defn user-extensions
  []
  [(extension-non-ca)
   (extension-key-usage typical-user-key-usage)
   (extension-extended-key-usage typical-user-extended-key-usage)])


;;;;;;;;;;
;; High level functions
;;;;;;;;;;

(defn generate-root-certificate
  "Generate self-signed root CA certificate using given ECGOST3412 keypair.
  Assume Subject = Issuer for root CA. Appropriate Extensions are set for root CA certificate.
  Returns self-signed root CA ^X509CertificateObject.
  Params:
  * `keypair` - ^KeyPair for root CA;
  * `subject` - String with subject info in X.500 distinguished name format.
     Example: \"CN=Red Stars Systems Root CA,OU=www.rssys.org,O=Red Stars Systems,C=RU\"
  Opts:
    `not-before-date` (optional) - ^Date object, by default current date and time
    `not-after-date` (optional) - ^Date object, by default current date and time + 30 years.
    `serial-number` (optional) - ^BigInteger object (max 20 bytes), by default - current milliseconds since 1970 + random integer.
    "
  ^X509CertificateObject
  [^KeyPair keypair ^String subject &
   {:keys [^Date not-before-date ^Date not-after-date ^BigInteger serial-number]}]
  (assert (string? subject) "Subject should be a string")
  (let [key-length       (s/-key-length (s/get-private keypair))
        issuer           subject
        algo-name        (condp = key-length
                           256 "GOST3411-2012-256withECGOST3410-2012-256"
                           512 "GOST3411-2012-512withECGOST3410-2012-512")
        calendar         (Calendar/getInstance)
        _                (.set calendar Calendar/MILLISECOND 0) ;; obfuscate millis
        not-before-date' ^Date (or not-before-date (.getTime calendar))
        not-after-date'  ^Date (or not-after-date (do (.add calendar Calendar/YEAR 30) (.getTime calendar)))
        serial-number'   ^BigInteger (or serial-number (BigInteger. (str (System/currentTimeMillis) (rand-int 10000000))))
        content-signer   (-> (JcaContentSignerBuilder. algo-name) (.setProvider "BC") (.build (s/get-private keypair)))
        cert-builder     (JcaX509v3CertificateBuilder. (X500Name. issuer) serial-number' not-before-date'
                           not-after-date' (X500Name. subject) (s/get-public keypair))
        cert-ext-utils   (JcaX509ExtensionUtils.)

        cert-builder'    (doto cert-builder
                           ;; set basic constraints to true to mark root certificate as CA certificate
                           (.addExtension (extension-ca))
                           (.addExtension (extension-key-usage typical-ca-key-usage))

                           (.addExtension Extension/subjectKeyIdentifier false (.createSubjectKeyIdentifier cert-ext-utils
                                                                                 (s/get-public keypair)))
                           (.addExtension Extension/authorityKeyIdentifier false (.createAuthorityKeyIdentifier cert-ext-utils
                                                                                   (s/get-public keypair))))

        cert-holder      (.build cert-builder' content-signer)]

    ;; generate certificate
    (-> (JcaX509CertificateConverter.)
      (.setProvider "BC")
      (.getCertificate cert-holder))))


(defn generate-csr
  ^PKCS10CertificationRequest
  [^KeyPair keypair ^String subject extension-coll]
  (let [key-length     (s/-key-length (s/get-private keypair))
        p10-builder    (JcaPKCS10CertificationRequestBuilder. (X500Name. subject) (s/get-public keypair))
        algo-name      (condp = key-length
                         256 "GOST3411-2012-256withECGOST3410-2012-256"
                         512 "GOST3411-2012-512withECGOST3410-2012-512")
        content-signer (-> (JcaContentSignerBuilder. algo-name) (.setProvider "BC") (.build (s/get-private keypair)))]
    (when (seq extension-coll)
      (.addAttribute p10-builder PKCSObjectIdentifiers/pkcs_9_at_extensionRequest (e-coll->extensions extension-coll)))
    (.build p10-builder content-signer)))


(defn csr->pem-string
  ^String
  [^PKCS10CertificationRequest csr]
  (pem/write-bytes-to-pem "CERTIFICATE REQUEST" (.getEncoded csr)))


(defn pem-string->csr
  ^PKCS10CertificationRequest
  [^String pem-csr]
  (PKCS10CertificationRequest. (pem/read-bytes-from-pem pem-csr)))



(defn generate-certificate
  ^X509CertificateObject
  [^X509CertificateObject ca-certificate ^KeyPair ca-keypair ^PKCS10CertificationRequest csr &
   {:keys [^Date not-before-date ^Date not-after-date ^BigInteger serial-number crl-uris
           ^Extensions required-extensions]}]
  (let [key-length       (s/-key-length (s/get-private ca-keypair))
        issuer           ^String (.getName (.getSubjectX500Principal ca-certificate))
        subject          (.getSubject csr)
        extensions       ^Extensions (or required-extensions (.getRequestedExtensions csr))
        algo-name        (condp = key-length
                           256 "GOST3411-2012-256withECGOST3410-2012-256"
                           512 "GOST3411-2012-512withECGOST3410-2012-512")
        calendar         (Calendar/getInstance)
        _                (.set calendar Calendar/MILLISECOND 0) ;; obfuscate millis
        not-before-date' ^Date (or not-before-date (.getTime calendar))
        not-after-date'  ^Date (or not-after-date (do (.add calendar Calendar/YEAR 2) (.getTime calendar)))

        serial-number'   ^BigInteger (or serial-number (BigInteger. (str (System/currentTimeMillis) (rand-int 10000000))))
        cert-builder     (JcaX509v3CertificateBuilder. (X500Name. issuer) serial-number' not-before-date'
                           not-after-date' subject (s/get-public ca-keypair))

        cert-ext-utils   (JcaX509ExtensionUtils.)

        cert-builder'    (doto cert-builder
                           (.addExtension Extension/authorityKeyIdentifier false (.createAuthorityKeyIdentifier cert-ext-utils
                                                                                   ca-certificate))
                           (.addExtension Extension/subjectKeyIdentifier false (.createSubjectKeyIdentifier cert-ext-utils
                                                                                 (.getSubjectPublicKeyInfo csr))))


        content-signer   (-> (JcaContentSignerBuilder. algo-name) (.setProvider "BC") (.build (s/get-private ca-keypair)))
        cert-builder''   (if crl-uris
                           (.addExtension cert-builder' (extension-crl crl-uris))
                           cert-builder')
        oids             (enumeration-seq (.oids extensions))
        cert-builder'''  (if (seq oids)
                           (reduce (fn [acc i] (.addExtension acc (.getExtension extensions i))) cert-builder'' oids)
                           cert-builder'')

        cert-holder      (.build cert-builder''' content-signer)]
    (-> (JcaX509CertificateConverter.)
      (.setProvider "BC")
      (.getCertificate cert-holder))))


(defn write-cert-der-file
  "Write X.509 certificate to a file in a binary form using DER format.
  Returns absolute path for filename if success or throws Exception if error."
  [^X509CertificateObject certificate ^String filename]
  (let [out (io/output-stream filename)]
    (.write out (.getEncoded certificate))
    (.close out)
    (.getAbsolutePath (io/file filename))))


(defn write-cert-pem-file
  "Write X.509 certificate to a file in a text form using PEM format.
  Returns absolute path for filename if success or throws Exception if error."
  [^X509CertificateObject certificate ^String filename]
  (let [pem-cert (pem/write-bytes-to-pem "CERTIFICATE" (.getEncoded certificate))]
    (spit filename pem-cert)
    (.getAbsolutePath (io/file filename))))


(defn read-cert-der-file
  "Read X.509 certificate from a file in a binary DER format.
  Returns ^X509CertificateObject"
  ^X509CertificateObject
  [^String filename]
  (Security/addProvider (BouncyCastleProvider.))
  (with-open [in (io/input-stream filename)]
    (let [x509-factory (CertificateFactory.)
          result       ^X509CertificateObject (.engineGenerateCertificate x509-factory in)]
      result)))


(defn read-cert-pem-file
  "Read X.509 certificate from a file in a text PEM format.
  Returns ^X509CertificateObject"
  ^X509CertificateObject
  [^String filename]
  (Security/addProvider (BouncyCastleProvider.))
  (with-open [in (io/input-stream (pem/read-bytes-from-pem (slurp filename)))]
    (let [x509-factory (CertificateFactory.)
          result       ^X509CertificateObject (.engineGenerateCertificate x509-factory in)]
      result)))


;; Read DER file via `openssl`
;; docker run --rm -v /Users/mike/projects/gost/c256.crt:/c256.crt -i -t rnix/openssl-gost openssl x509 -in c256.crt -inform der -text

;; Read PEM file via `openssl`
;; docker run --rm -v /Users/mike/projects/gost/c512.pem:/c512.pem -i -t rnix/openssl-gost openssl x509 -in c512.pem -text


;; docker run --rm -v /Users/mike/projects/gost/a.csr:/a.csr -i -t rnix/openssl-gost openssl req -in a.csr -noout -text
