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
    (org.bouncycastle.asn1.x500
      X500Name)
    (org.bouncycastle.asn1.x509
      BasicConstraints
      Extension
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
      JcaContentSignerBuilder)))


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
  [^KeyPair keypair ^String subject & {:keys [^Date not-before-date ^Date not-after-date ^BigInteger serial-number]}]
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
                           (.addExtension Extension/basicConstraints true (BasicConstraints. true))
                           (.addExtension Extension/subjectKeyIdentifier false (.createSubjectKeyIdentifier cert-ext-utils
                                                                                 (s/get-public keypair)))
                           (.addExtension Extension/keyUsage true (KeyUsage. (bit-or KeyUsage/keyCertSign KeyUsage/cRLSign
                                                                               KeyUsage/digitalSignature)))
                           (.addExtension Extension/authorityKeyIdentifier false (.createAuthorityKeyIdentifier cert-ext-utils
                                                                                   (s/get-public keypair))))

        cert-holder      (.build cert-builder' content-signer)]

    ;; generate certificate
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

