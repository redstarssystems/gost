(ns examples.ecies
  (:require
    [org.rssys.gost.ecies :as ecies]
    [org.rssys.gost.sign :as s]))


;; Generate Alice keypair 256-bit length
(def alice-kp (s/gen-keypair-256))

(def alice-private-key (s/get-private alice-kp))
(def alice-public-key (s/get-public alice-kp))


;; Generate Bob keypair 256-bit length
(def bob-kp (s/gen-keypair-256))

(def bob-private-key (s/get-private bob-kp))
(def bob-public-key (s/get-public bob-kp))


(def message "This is message.")


;; Alice encrypts message with one-time secret key 256-bit length derived from
;; Bob's public key and Alice's private key and random vector. Random vector is encrypted with ECIES and Bob's public key.
(def encrypted-data (ecies/encrypt-bytes alice-private-key bob-public-key (.getBytes message)))


;; Bob decrypts message with one-time secret key 256-bit length derived from
;; Bob's private key and Alice public key and random vector. Random vector is decrypted with ECIES and Bob's private key.
(String. ^bytes (ecies/decrypt-bytes bob-private-key alice-public-key encrypted-data))


;; Generate Alice keypair 512-bit length
(def alice-kp-512 (s/gen-keypair-512))

(def alice-private-key-512 (s/get-private alice-kp-512))
(def alice-public-key-512 (s/get-public alice-kp-512))


;; Generate Bob keypair 512-bit length
(def bob-kp-512 (s/gen-keypair-512))

(def bob-private-key-512 (s/get-private bob-kp-512))
(def bob-public-key-512 (s/get-public bob-kp-512))


(def message2 "This is message2.")


;; Alice encrypts message2 with one-time secret key 256-bit length derived from
;; Bob's public key and Alice's private key and random vector. Random vector is encrypted with ECIES and Bob's public key.
(def encrypted-data2 (ecies/encrypt-bytes alice-private-key-512 bob-public-key-512 (.getBytes message2)))


;; Bob decrypts message2 with one-time secret key 256-bit length derived from
;; Bob's private key and Alice's public key and random vector. Random vector is decrypted with ECIES and Bob's private key.
(String. ^bytes (ecies/decrypt-bytes bob-private-key-512 alice-public-key-512 encrypted-data2))


;; Alice encrypts file with one-time secret key 256-bit length derived from
;; Bob's public key and Alice's private key and random vector. Random vector is encrypted with ECIES and Bob's public key.
(ecies/encrypt-file alice-private-key bob-public-key "test/data/big.txt" "target/big.egz")


;; Bob decrypts file with one-time secret key 256-bit length derived from
;; Bob's private key and Alice's public key and random vector. Random vector is decrypted with ECIES and Bob's private key.
(ecies/decrypt-file bob-private-key alice-public-key "target/big.egz" "target/big.txt")

(= (slurp "test/data/big.txt") (slurp "target/big.txt"))    ;; => true
