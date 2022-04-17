(ns examples.p12store
  "Examples for PKCS12 functions"
  (:require
    [org.rssys.gost.cert :as cert]
    [org.rssys.gost.encrypt :as e]
    [org.rssys.gost.p12store :as p12store]
    [org.rssys.gost.sign :as s]))


;; Generate ECGOST3410-2012 512-bit length keypair
(def kp-512 (s/gen-keypair-512))


;; Generate self-signed root CA certificate
(def cert-512 (cert/generate-root-certificate kp-512 "cn=rootca"))


;; Create empty KeyStore in memory
(def ks (p12store/create-keystore))


;; Set private key with certificate chain to a keystore
(p12store/set-private-key ks (s/get-private kp-512) "privatekey" [cert-512])


;; List aliases in a KeyStore
(p12store/list-aliases ks)                                  ;; => ["privatekey"]

;; Generate secret key
(def secret-key (e/generate-secret-key))


;; Set secret key entry to a KeyStore
(p12store/set-secret-key ks secret-key "secretkey")


;; Read secret key entry from a KeyStore
(def restored-secret-key (p12store/get-secret-key ks "secretkey"))


;; Check that keys are equal
(= restored-secret-key secret-key)


;; Check if KeyStore contains given alias
(p12store/contains-alias? ks "secretkey")


;; Delete entry with given alias from KeyStore
(p12store/delete-entry ks "secretkey")


;; Set secret key entry to a KeyStore encrypted with `PBEWithHmacSHA256AndAES_256` algorithm
(p12store/set-secret-key ks secret-key "secretkey2" :password "Secret13")


;; Read secret key entry from a KeyStore using given password for decryption key entry
(def restored-secret-key2 (p12store/get-secret-key ks "secretkey2" :password "Secret13"))


;; Set private key with certificate chain to a keystore encrypted with password entry
;; using `PBEWithHmacSHA256AndAES_256` algorithm
(p12store/set-private-key ks (s/get-private kp-512) "privatekey2" [cert-512] :password "Secret13")


;; Write KeyStore to a file
(p12store/write-keystore ks "ks.p12" "Secret13")


;; Read KeyStore from file
(def restored-ks (p12store/read-keystore "ks.p12" "Secret13"))


;; List aliases in a KeyStore
(p12store/list-aliases restored-ks)                         ;; =>
;;["privatekey" "secretkey2" "privatekey2"]



