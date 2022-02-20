(ns examples.sign
  (:require
    [org.rssys.gost.digest :as d]
    [org.rssys.gost.sign :as s]))


(def message "This is a message.")


;; Generate public and private keypair 256 bit length
(def kp-256 (s/gen-keypair-256))

(def public-key-256 (.getPublic kp-256))
(def private-key-256 (.getPrivate kp-256))


;; Generate signature for byte array.
;; Digest GOST3411-2012 256-bit length for message will be calculated automatically.
(def signature-256 (s/sign-256 private-key-256 (.getBytes message)))


;; Check signature length
(alength signature-256)                                     ;; => 64

;; Check signature using public key
(s/verify-256 public-key-256 (.getBytes message) signature-256) ;; => true

;; Generate public and private keypair 512 bit length
(def kp-512 (s/gen-keypair-512))

(def public-key-512 (.getPublic kp-512))
(def private-key-512 (.getPrivate kp-512))


;; Generate signature for a file.
;; Digest GOST3411-2012 512 bit length for file content will be calculated automatically.
(def signature-512 (s/sign-512 private-key-512 "test/data/big.txt"))


;; Check signature length
(alength signature-512)                                     ;; => 128

;; Check signature of file using public key
(s/verify-512 public-key-512 "test/data/big.txt" signature-512) ;; => true
