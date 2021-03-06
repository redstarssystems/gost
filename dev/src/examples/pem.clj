(ns examples.pem
  (:require
    [org.rssys.gost.encrypt :as e]
    [org.rssys.gost.pem :as p]
    [org.rssys.gost.sign :as s]))


;; Generate public and private keypair 256 bit length
(def kp-256 (s/gen-keypair-256))

(def public-key-256 (.getPublic kp-256))
(def private-key-256 (.getPrivate kp-256))


;; To save private key to encrypted PEM (PKCS8) string use `private-key->encrypted-pem`
;; Private key will be encrypted with AES-256-CBC in `openssl` format.
(p/private-key->encrypted-pem private-key-256 "123456")     ;; =>
;; "-----BEGIN ENCRYPTED PRIVATE KEY-----
;;MIGpMFUGCSqGSIb3DQEFDTBIMCcGCSqGSIb3DQEFDDAaBBSMtRpFQ6n7RgZTriGG
;;bFr8JJeKiQICBAAwHQYJYIZIAWUDBAEqBBB0XmFK1rvMBnC4t7BSGndLBFDiON0S
;;e1iGKb80u/lLXti1+7x9QKCGZtVIJw62YIQWAxy7zK5vZ1xAQxSRNjssfi0niroL
;;0ZqRJpFb6czeCFyq2HBzUvNH2rRdAiRv91KDgg==
;;-----END ENCRYPTED PRIVATE KEY-----
;;"

;; To restore private key from encrypted PEM (PKCS8) string use `encrypted-pem->private-key`
(p/encrypted-pem->private-key (slurp "test/data/test-encrypted-private-key.pem") "123456") ;; =>
;;#object[org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PrivateKey 0x3776cb5 "ECGOST3410-2012
;; Private Key [55:07:ef:03:d1:7f:ea:e7:53:ca:58:6d:0e:da:0a:6f:e2:93:4b:b4]
;;            X: df0679d81ec2156f062b507918c10fb9e680848be92ec69af6be9f32ffd8669e
;;            Y: 2234280a15135e723579ef96544742f6cc06f8d59cccd88fd4b377f818ce9f95
;;"]

;; Also, you can use _openssl_ with _GOST_ support to read PEM private key.
;;Download _openssl_ with _GOST_ from here: `docker run --rm -i -t rnix/openssl-gost bash`.

;; Convert PrivateKey to PEM string
;; Warning: PEM string will be not encrypted!
(def private-pem-256 (p/private-key->pem private-key-256))


;; Convert PublicKey to PEM string
(def public-pem-256 (p/public-key->pem public-key-256))


;; Convert PEM string to a PrivateKey
(def restored-private-256 (p/pem->private-key private-pem-256))


;; check that keys are equal
(= restored-private-256 private-key-256)


;; Convert PEM string to a PublicKey
(def restored-public-256 (p/pem->public-key public-pem-256))


;; check that keys are equal
(= restored-public-256 public-key-256)


;; to read PEM private key:
;;openssl pkey -in test/data/test-private-key.pem -noout -text


;;to read PEM public key.
;;openssl pkey -pubin -in test/data/test-public-key.pem -text


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


;; You can write to PEM format arbitrary byte array
(p/write-bytes-to-pem "MESSAGE" (.getBytes "Hello"))


;; You can read from PEM arbitrary byte array
(String. (p/read-bytes-from-pem "-----BEGIN MESSAGE-----\nSGVsbG8=\n-----END MESSAGE-----\n"))


;; You can write structured data to PEM format
(p/write-struct-to-pem {:data (.getBytes "Hello") :type "MESSAGE" :headers {:status "unencrypted" :date "01-01-2022"}}) ;; =>
;; "-----BEGIN MESSAGE-----
;;status: unencrypted
;;date: 01-01-2022
;;
;;SGVsbG8=
;;-----END MESSAGE-----
;;"

;; You can read structured data from PEM string
(p/read-struct-from-pem (slurp "test/data/test-plain-with-headers.pem")) ;; =>
;;{:data [72, 101, 108, 108, 111],
;; :type "MESSAGE",
;; :headers {"status" "unencrypted", "date" "01-01-2022"}}

(def message "Hello, world!")
(def input (.getBytes message))


;; Sign message
(def signature (s/sign-256 private-key-256 input))


;; Create detached signature as PEM string
(def signature-pem (p/write-bytes-to-pem "SIGNATURE" signature))


;; Restore signature from PEM string
(def restored-signature (p/read-bytes-from-pem signature-pem))


;; Verify restored signature
(s/verify-256 public-key-256 input restored-signature)


;; Generate secret key
(def secret-key-2015 (e/generate-secret-key))


;; PEM string with plain secret key
;; Warning: PEM string will be not encrypted!
(def pem-secret-key-2015 (p/secret-key->pem secret-key-2015))


;; Restore secret key from plain PEM
(def restored-secret-key-2015 (p/pem->secret-key pem-secret-key-2015))


;; Check that keys are equal
(= restored-secret-key-2015 secret-key-2015)


;; Convert SecretKeySpec to encrypted PEM string
;; Secret key will be encrypted with key derived from PBKDF2(`password`) using GOST3412-2015-CBC"
(def encrypted-pem-secret-key (p/secret-key->encrypted-pem secret-key-2015 "123456"))


;; Restore secret key from encrypted PEM
;; Secret key will be decrypted with key derived from PBKDF2(`password`) using GOST3412-2015-CBC"
(def restored-encrypted-secret-key-2015 (p/encrypted-pem->secret-key encrypted-pem-secret-key "123456"))


;; Check that keys are equal
(= restored-encrypted-secret-key-2015 secret-key-2015)
