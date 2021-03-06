(ns examples.cert
  (:require
    [org.rssys.gost.cert :as cert]
    [org.rssys.gost.sign :as s])
  (:import
    (java.util
      Calendar)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generate self-signed root CA certificate

;; Generate root CA keypair
(def root-ca-keypair (s/gen-keypair-512))


;; Subject is a String in X.500 distinguished name format.
(def root-ca-subject "CN=Red Stars Systems Root CA,OU=www.rssys.org,O=Red Stars Systems,C=RU")


;; Generate self-signed root CA certificate.
(def root-ca-cert (cert/generate-root-certificate root-ca-keypair root-ca-subject))


;; Write X.509 root CA certificate to a file in a binary form using DER format.
(cert/write-cert-der-file root-ca-cert "target/root-ca-512.crt")


;; You can read root CA certificate using `openssl` with GOST support from DER file.
;; docker run --rm -v /Users/mike/projects/gost/target/root-ca-512.crt:/root-ca-512.crt -i -t rnix/openssl-gost openssl x509 -in root-ca-512.crt -inform der -text

;; Write X.509 root CA certificate to a file in a text form using PEM format.
(cert/write-cert-pem-file root-ca-cert "target/root-ca-512.pem")


;; You can read root CA certificate using `openssl` with GOST support from PEM file
;; docker run --rm -v /Users/mike/projects/gost/target/root-ca-512.pem:/root-ca-512.pem -i -t rnix/openssl-gost openssl x509 -in root-ca-512.pem -text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generate web server certificate

;; Generate web server keypair
(def webserver-keypair (s/gen-keypair-512))


;; Subject is a String in X.500 distinguished name format.
(def webserver-subject "CN=www.rssys.org")


;; Generate webserver CSR with typical extensions for TLS server, and given alternative names.
(def webserver-csr (cert/generate-csr webserver-keypair webserver-subject (cert/webserver-extensions ["www.rssys.org"])))


;; Write webserver CSR to a file
(spit "target/webserver.csr" (cert/csr->pem-string webserver-csr))


;; You can read CSR using `openssl` with GOST support from PEM file:
;; docker run --rm -v /Users/mike/projects/gost/target/webserver.csr:/webserver.csr -i -t rnix/openssl-gost openssl req -in webserver.csr -text


;; get current date + 2 years
(def webserver-not-after-date (.getTime (doto (Calendar/getInstance) (.add Calendar/YEAR 2))))


;; Generate web server certificate valid for 2 years (default) with extensions from CSR
(def webserver-cert (cert/generate-certificate root-ca-cert root-ca-keypair webserver-csr))


;; Generate web server certificate valid for 2 years with extensions from CSR
;; and add some extra extensions from `:merge-extensions`
(def webserver-cert
  (cert/generate-certificate root-ca-cert root-ca-keypair webserver-csr
    {:not-after-date webserver-not-after-date
     :merge-extensions (cert/e-coll->extensions
                         [(cert/extension-crl ["https://ca.rssys.org/crl.pem"])
                          (cert/extension-ocsp-access-info ["https://ca.rssys.org/ocsp"])])}))


;; Generate web server certificate valid for 2 years with explicit extensions from `:override-extensions`
;; (not from CSR) and add some extra extensions from `:merge-extensions`
(def webserver-cert'
  (cert/generate-certificate root-ca-cert root-ca-keypair webserver-csr
    {:not-after-date      webserver-not-after-date
     :override-extensions (cert/e-coll->extensions
                            (cert/webserver-extensions ["www.rssys.org"]))
     :merge-extensions (cert/e-coll->extensions
                         [(cert/extension-crl ["https://ca.rssys.org/crl.pem"])
                          (cert/extension-ocsp-access-info ["https://ca.rssys.org/ocsp"])])}))


;; Write X.509 webserver certificate to a file in a binary form using DER format.
(cert/write-cert-der-file webserver-cert "target/webserver.crt")


;; You can read certificate using `openssl` with GOST support from DER file.
;; docker run --rm -v /Users/mike/projects/gost/target/webserver.crt:/webserver.crt -i -t rnix/openssl-gost openssl x509 -in webserver.crt -inform der -text


;; Write X.509 webserver certificate to a file in a text form using PEM format.
(cert/write-cert-pem-file webserver-cert' "target/webserver.pem")


;; You can read webserver certificate using `openssl` with GOST support from PEM file
;; docker run --rm -v /Users/mike/projects/gost/target/webserver.pem:/webserver.pem -i -t rnix/openssl-gost openssl x509 -in webserver.pem -text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generate end user certificate

;; Generate user keypair 512-bit length
(def user-keypair (s/gen-keypair-512))


;; Subject is a String in X.500 distinguished name format
(def user-subject "CN=Tony Stark,OU=Investigations,O=Red Stars Systems,C=RU")


;; get current date + 2 years
(def user-not-after-date (.getTime (doto (Calendar/getInstance) (.add Calendar/YEAR 2))))


;; Generate end user CSR with typical extensions for TLS client
(def user-csr (cert/generate-csr user-keypair user-subject (cert/user-extensions)))


;; Write user CSR to a file as PEM string
(spit "target/user.csr" (cert/csr->pem-string user-csr))


;; You can read CSR using `openssl` with GOST support from PEM file:
;; docker run --rm -v /Users/mike/projects/gost/target/user.csr:/user.csr -i -t rnix/openssl-gost openssl req -in user.csr -text


;; Generate user certificate valid for 2 years (default) with extensions from CSR
(def user-cert (cert/generate-certificate root-ca-cert root-ca-keypair user-csr))


;; Generate user certificate with some params and extensions from CSR and merge-extensions.
(def user-cert
  (cert/generate-certificate root-ca-cert root-ca-keypair user-csr
    {:not-after-date   user-not-after-date
     :merge-extensions (cert/e-coll->extensions
                         [(cert/extension-crl ["https://ca.rssys.org/crl.pem"])
                          (cert/extension-ocsp-access-info ["https://ca.rssys.org/ocsp"])])}))


;; Generate user certificate valid for 2 years with explicitly set extensions from
;; :override-extensions (not from CSR)
(def user-cert'
  (cert/generate-certificate root-ca-cert root-ca-keypair user-csr
    {:not-after-date      user-not-after-date
     :override-extensions (cert/e-coll->extensions
                            (conj
                              (cert/user-extensions)
                              (cert/extension-crl ["https://ca.rssys.org/crl.pem"])
                              (cert/extension-ocsp-access-info ["https://ca.rssys.org/ocsp"])))}))


;; Write X.509 user certificate to a file in a binary form using DER format.
(cert/write-cert-der-file user-cert "target/user.crt")


;; You can read certificate using `openssl` with GOST support from DER file.
;; docker run --rm -v /Users/mike/projects/gost/target/user.crt:/user.crt -i -t rnix/openssl-gost openssl x509 -in user.crt -inform der -text


;; Write X.509 user certificate to a file in a text form using PEM format.
(cert/write-cert-pem-file user-cert' "target/user.pem")


;; You can read user certificate using `openssl` with GOST support from PEM file
;; docker run --rm -v /Users/mike/projects/gost/target/user.pem:/user.pem -i -t rnix/openssl-gost openssl x509 -in user.pem -text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Other functions

;; Read X.509 root CA certificate from a binary DER file.
(def restored-der-root-cert-512 (cert/read-cert-der-file "target/root-ca-512.crt"))
(= restored-der-root-cert-512 root-ca-cert)                 ;; => true

;; Read X.509 root CA certificate from a text PEM file.
(def restored-pem-root-cert-512 (cert/read-cert-pem-file "target/root-ca-512.pem"))
(= restored-pem-root-cert-512 root-ca-cert)                 ;; => true


;; Get collection of ^Extension objects from certificate
(cert/get-cert-extensions user-cert)


;; Get collection of ^DistributionPoint objects for given certificate
(cert/get-cert-crl user-cert')


;; Get collection of ^AccessDescription objects for given certificate (OCSP access points, etc.).
(def ocsp-coll (cert/get-cert-authority-access-info user-cert'))


;; Get first OCSP URL from collection
(.toString (.getName ^org.bouncycastle.asn1.x509.GeneralName (.getAccessLocation (first ocsp-coll))))
