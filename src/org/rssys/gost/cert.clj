(ns org.rssys.gost.cert
  "X.509 certificates functions"
  (:require
    [clojure.java.io :as io]
    [org.rssys.gost.pem :as pem]
    [org.rssys.gost.sign :as s])
  (:import
    (java.io
      ByteArrayInputStream)
    (java.security
      KeyPair
      Security)
    (java.util
      Calendar
      Date)
    (org.bouncycastle.asn1
      ASN1InputStream
      ASN1ObjectIdentifier
      DEROctetString)
    (org.bouncycastle.asn1.pkcs
      PKCSObjectIdentifiers)
    (org.bouncycastle.asn1.x500
      X500Name)
    (org.bouncycastle.asn1.x509
      AccessDescription
      AuthorityInformationAccess
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
      KeyUsage
      X509ObjectIdentifiers)
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
  "Returns ^Extension for collection of Strings for alternative names.
   Example: [\"rssys.org\"]."
  ^Extension
  [alt-names]
  (let [gen-names (map #(GeneralName. GeneralName/dNSName ^String %) alt-names)]
    (Extension. Extension/subjectAlternativeName
      false
      (DEROctetString. ^GeneralNames (GeneralNames.
                                       ^"[Lorg.bouncycastle.asn1.x509.GeneralName;"
                                       (into-array GeneralName gen-names))))))


(defn extension-crl
  "Returns ^Extension for collection of URI for CRL distribution points.
   Example: [\"http://localhost/crl.pem\"]."
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


(defn extension-ocsp-access-info
  "Returns ^Extension for collection of URI for OCSP of authority access information.
   Example: [\"http://localhost/ocsp\"]."
  ^Extension
  [ocsp-uris]
  (let [aai-points (map #(AccessDescription.
                           X509ObjectIdentifiers/ocspAccessMethod
                           (GeneralName. GeneralName/uniformResourceIdentifier ^String %))
                     ocsp-uris)
        aia        (AuthorityInformationAccess. ^"[Lorg.bouncycastle.asn1.x509.AccessDescription;"
                     (into-array AccessDescription aai-points))]
    (Extension. Extension/authorityInfoAccess false (.getEncoded aia))))


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
  "Convert collection of ^Extension objects to ^Extensions object."
  ^Extensions
  [e-coll]
  (Extensions. ^"[Lorg.bouncycastle.asn1.x509.Extension;" (into-array Extension e-coll)))


(defn ca-extensions
  "Returns collection of ^Extension objects for typical CA certificate."
  ^"[Lorg.bouncycastle.asn1.x509.Extension;"
  []
  [(extension-ca)
   (extension-key-usage typical-ca-key-usage)])


(defn webserver-extensions
  "Returns collection of ^Extension objects for typical web server certificate.
  Params:
  * `alternative-names` - ^String collection with alternative name, e.g. [\"www.site.com\"]"
  ^"[Lorg.bouncycastle.asn1.x509.Extension;"
  [alternative-names]
  [(extension-non-ca)
   (extension-key-usage typical-web-server-key-usage)
   (extension-extended-key-usage typical-web-server-extended-key-usage)
   (extension-alternative-names alternative-names)])


(defn user-extensions
  "Returns collection of ^Extension objects for typical end user certificate."
  ^"[Lorg.bouncycastle.asn1.x509.Extension;"
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
  "Generate Certificate Request (CSR) for given `keypair`.
  Returns ^PKCS10CertificationRequest objects.

  Params:
  * `keypair` - ^KeyPair object for CSR.
  * `subject` - ^String in X.500 distinguished name format. Example: \"CN=John Doe,OU=Finance,O=Red Stars Systems,C=RU\",
  * `extension-coll` - collection of ^Extension objects for CSR."
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
  "Convert ^PKCS10CertificationRequest (CSR) object to PEM string.
  Returns ^String."
  ^String
  [^PKCS10CertificationRequest csr]
  (pem/write-bytes-to-pem "CERTIFICATE REQUEST" (.getEncoded csr)))


(defn pem-string->csr
  "Convert PEM string into Certificate Request (CSR) object.
  Returns ^PKCS10CertificationRequest object."
  ^PKCS10CertificationRequest
  [^String pem-csr]
  (PKCS10CertificationRequest. (pem/read-bytes-from-pem pem-csr)))


(defn get-cert-extensions
  "Return collection of ^Extension object from certificate ^X509CertificateObject object."
  ^"[Lorg.bouncycastle.asn1.x509.Extension;"
  [^X509CertificateObject cert]
  (let [extension-builder-fn (fn [^Boolean flag]
                               (fn [acc ^String i]
                                 (let [oid-bytes   (.getExtensionValue cert i)
                                       asn1-stream (ASN1InputStream. (ByteArrayInputStream. oid-bytes))
                                       der-object  (.readObject asn1-stream)]
                                   (conj acc (Extension. (ASN1ObjectIdentifier. i)
                                               flag ^DEROctetString (cast DEROctetString der-object))))))]
    (flatten
      (conj
        (reduce (extension-builder-fn true) [] (.getCriticalExtensionOIDs cert))
        (reduce (extension-builder-fn false) [] (.getNonCriticalExtensionOIDs cert))))))


(defn get-cert-crl
  "Returns collection of ^DistributionPoint objects for given certificate."
  ^"[Lorg.bouncycastle.asn1.x509.DistributionPoint;"
  [^X509CertificateObject cert]
  (if-let [oid-bytes (.getExtensionValue cert (.getId Extension/cRLDistributionPoints))]
    (let [asn1-stream (ASN1InputStream. (ByteArrayInputStream. oid-bytes))
          der-object  (.readObject asn1-stream)
          octets      (.getOctets (cast DEROctetString der-object))
          crls        (CRLDistPoint/getInstance (.readObject (ASN1InputStream. (ByteArrayInputStream. octets))))]
      (.getDistributionPoints crls))
    []))


(defn get-cert-authority-access-info
  "Returns collection of ^AccessDescription objects for given certificate (OCSP etc.)."
  ^"[Lorg.bouncycastle.asn1.x509.AccessDescription;"
  [^X509CertificateObject cert]
  (if-let [oid-bytes (.getExtensionValue cert (.getId Extension/authorityInfoAccess))]
    (let [asn1-stream (ASN1InputStream. (ByteArrayInputStream. oid-bytes))
          der-object  (.readObject asn1-stream)
          octets      (.getOctets (cast DEROctetString der-object))
          auth-info   (AuthorityInformationAccess/getInstance
                        (.readObject (ASN1InputStream. (ByteArrayInputStream. octets))))]
      (.getAccessDescriptions auth-info))
    []))



(defn generate-certificate
  "Generate a certificate for given Certificate request (CSR).
  Returns a certificate ^X509CertificateObject signed by CA keypair.

  Params:
  * `ca-certificate` - ^X509CertificateObject CA certificate,
  * `ca-keypair` - ^KeyPair CA keypair,
  * `csr` - ^PKCS10CertificationRequest CSR which should be signed by CA.

  Opts:
  * `not-before-date` (optional) - ^Date object, by default current date and time.
  * `not-after-date` (optional) - ^Date object, by default current date and time + 2 years.
  * `serial-number` (optional) - ^BigInteger object (max 20 bytes),
     by default - current milliseconds since 1970 + random integer,
  * `override-extensions` (optional) - collection of ^Extension objects which should be explicitly set into certificate.
  CSR extensions will be ignored. If not set, then extensions will be taken from CSR and set into certificate.
  * `merge-extensions` (optional) - collection of ^Extension objects which should be added to CSR/override-extensions."
  ^X509CertificateObject
  [^X509CertificateObject ca-certificate ^KeyPair ca-keypair ^PKCS10CertificationRequest csr &
   {:keys [^Date not-before-date ^Date not-after-date ^BigInteger serial-number
           ^Extensions override-extensions ^Extensions merge-extensions]}]
  (let [key-length          (s/-key-length (s/get-private ca-keypair))
        issuer              ^String (.getName (.getSubjectX500Principal ca-certificate))
        subject             (.getSubject csr)
        required-extensions ^Extensions (or override-extensions (.getRequestedExtensions csr))
        merge-extensions    ^Extensions (or merge-extensions
                                          (Extensions. ^"[Lorg.bouncycastle.asn1.x509.Extension;" ;; empty Extensions
                                            (into-array Extension [])))
        algo-name           (condp = key-length
                              256 "GOST3411-2012-256withECGOST3410-2012-256"
                              512 "GOST3411-2012-512withECGOST3410-2012-512")
        calendar            (Calendar/getInstance)
        _                   (.set calendar Calendar/MILLISECOND 0) ;; obfuscate millis
        not-before-date'    ^Date (or not-before-date (.getTime calendar))
        not-after-date'     ^Date (or not-after-date (do (.add calendar Calendar/YEAR 2) (.getTime calendar)))

        serial-number'      ^BigInteger (or serial-number (BigInteger. (str (System/currentTimeMillis) (rand-int 10000000))))
        cert-builder        (JcaX509v3CertificateBuilder. (X500Name. issuer) serial-number' not-before-date'
                              not-after-date' subject (s/get-public ca-keypair))

        cert-ext-utils      (JcaX509ExtensionUtils.)

        cert-builder'       (doto cert-builder
                              (.addExtension Extension/authorityKeyIdentifier false (.createAuthorityKeyIdentifier cert-ext-utils
                                                                                      ca-certificate))
                              (.addExtension Extension/subjectKeyIdentifier false (.createSubjectKeyIdentifier cert-ext-utils
                                                                                    (.getSubjectPublicKeyInfo csr))))


        content-signer      (-> (JcaContentSignerBuilder. algo-name) (.setProvider "BC") (.build (s/get-private ca-keypair)))


        required-oids       (enumeration-seq (.oids required-extensions))

        cert-builder''      (if (seq required-oids)
                              (reduce (fn [acc i] (.addExtension acc (.getExtension required-extensions i))) cert-builder' required-oids)
                              cert-builder')

        merge-oids          (enumeration-seq (.oids merge-extensions))

        cert-builder'''     (if (seq merge-oids)
                              (reduce (fn [acc i] (.addExtension acc (.getExtension merge-extensions i))) cert-builder'' merge-oids)
                              cert-builder'')

        cert-holder         (.build cert-builder''' content-signer)]
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

