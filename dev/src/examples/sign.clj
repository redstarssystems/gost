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

;; Generate shared secret key 256-bit length using Elliptic-curve Diffie–Hellman (ECDH) algorithm.
;; Generate Alice keypair
(def alice-kp (s/gen-keypair-256))

(def alice-private-key (s/get-private alice-kp))
(def alice-public-key (s/get-public alice-kp))


;; Generate Bob keypair
(def bob-kp (s/gen-keypair-256))

(def bob-private-key (s/get-private bob-kp))
(def bob-public-key (s/get-public bob-kp))


;; Generate random bytes which should be known for Alice and Bob
;; `random-iv` is not secret and may be transferred via open channels.
;; Recommended length is 16+ random bytes for generate-shared-secret-256
;; and 32+ bytes for generate-shared-secret-512.
(def random-iv (s/random-bytes 16))


;; Generate shared secret 256-bits length for Alice
(def alice-shared-secret (s/generate-shared-secret-256 alice-private-key bob-public-key random-iv))


;; Generate shared secret 256-bits length for Bob
(def bob-shared-secret (s/generate-shared-secret-256 bob-private-key alice-public-key random-iv))


;; Check that keys are equal
(= (into [] alice-shared-secret) (into [] bob-shared-secret)) ;; => true
