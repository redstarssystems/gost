(ns examples.cert
  (:require
    [org.rssys.gost.cert :as cert]
    [org.rssys.gost.sign :as s]
    [clojure.java.io :as io])
  (:import
    (java.util
      Calendar)
    (java.security KeyStore KeyStore$PrivateKeyEntry KeyStore$PasswordProtection)
    (java.io ByteArrayOutputStream)
    (java.security.cert Certificate X509Certificate)))


;; Generate keypair 256-bit length
(def kp-256 (s/gen-keypair-256))


;; Subject is a String in X.500 distinguished name format
(def subject "CN=Red Stars Systems Root CA,OU=www.rssys.org,O=Red Stars Systems,C=RU")


;; get current date + 30 years
(def not-after-date (.getTime (doto (Calendar/getInstance) (.add Calendar/YEAR 30))))


;; Generate self-signed root CA certificate.
;; Assume Issuer = Subject for root CA. Appropriate Extensions are set for root CA certificate.
(def root-cert-256 (cert/generate-root-certificate kp-256 subject :not-after-date not-after-date))


;; Write X.509 root CA certificate to a file in a binary form using DER format.
(cert/write-cert-der-file root-cert-256 "target/root-ca-256.crt")


;; You can read root CA certificate using `openssl` with GOST support from DER file
;; docker run --rm -v /Users/mike/projects/gost/target/root-ca-256.crt:/root-ca-256.crt -i -t rnix/openssl-gost openssl x509 -in root-ca-256.crt -inform der -text


;; Write X.509 root CA certificate to a file in a text form using PEM format.
(cert/write-cert-pem-file root-cert-256 "target/root-ca-256.pem")


;; You can read root CA certificate using `openssl` with GOST support from PEM file
;; docker run --rm -v /Users/mike/projects/gost/target/root-ca-256.pem:/root-ca-256.pem -i -t rnix/openssl-gost openssl x509 -in root-ca-256.pem -text

;; Read X.509 root CA certificate from a binary DER file.
(def restored-der-root-cert-256 (cert/read-cert-der-file "target/root-ca-256.crt"))
(= restored-der-root-cert-256 root-cert-256)                ;; => true

;; Read X.509 root CA certificate from a text PEM file.
(def restored-pem-root-cert-256 (cert/read-cert-pem-file "target/root-ca-256.pem"))
(= restored-pem-root-cert-256 root-cert-256)                ;; => true
