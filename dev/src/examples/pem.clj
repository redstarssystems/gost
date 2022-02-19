(ns examples.pem
  (:require
    [org.rssys.gost.pem :as p]
    [org.rssys.gost.sign :as s]))


;; Generate public and private keypair 256 bit length
(def kp-256 (s/gen-keypair-256))

(def public-key-256 (.getPublic kp-256))
(def private-key-256 (.getPrivate kp-256))


;; Convert PrivateKey to PEM string
;; Warning: PEM string is not encrypted!
(def private-pem-256 (p/private-key->pem private-key-256))


;; Convert PublicKey to PEM string
(def public-pem-256 (p/public-key->pem public-key-256))


;; Convert PEM string to a PrivateKey
(def restored-private-256 (p/pem->private-key private-pem-256))


;; check that keys are equal
(= restored-private-256 private-key-256)


;; Also, you can use command to read PEM private key.
;;openssl pkey -in private-key.pem -noout -text


;; Convert PEM string to a PublicKey
(def restored-public-256 (p/pem->public-key public-pem-256))


;; check that keys are equal
(= restored-public-256 public-key-256)


;; Generate public and private keypair 512 bit length
(def kp-512 (s/gen-keypair-512))

(def public-key-512 (.getPublic kp-512))
(def private-key-512 (.getPrivate kp-512))


;; Convert PrivateKey to PEM string
;; Warning: PEM string is not encrypted!
(def private-pem-512 (p/private-key->pem private-key-512))


;; Convert PublicKey to PEM string
(def public-pem-512 (p/public-key->pem public-key-512))


;; Convert PEM string to a PrivateKey
(def restored-private-512 (p/pem->private-key private-pem-512))


;; check that keys are equal
(= restored-private-512 private-key-512)


;; Convert PEM string to a PublicKey
(def restored-public-512 (p/pem->public-key public-pem-512))


;; check that keys are equal
(= restored-public-512 public-key-512)
