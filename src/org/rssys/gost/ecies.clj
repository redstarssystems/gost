(ns org.rssys.gost.ecies
  "Encrypt/decrypt data using EC keys"
  (:require
    [clojure.java.io :as io]
    [org.rssys.gost.digest :as d]
    [org.rssys.gost.encrypt :as e]
    [org.rssys.gost.sign :as s])
  (:import
    (java.io
      ByteArrayOutputStream)
    (javax.crypto
      Cipher)
    (org.bouncycastle.jcajce.provider.asymmetric.ecgost12
      BCECGOST3410_2012PrivateKey
      BCECGOST3410_2012PublicKey)))


(defn encrypt-bytes
  "Encrypt bytes using EC keys.
  Data will be encrypted with one-time secret key 256-bit length.
  One-time secret key is derived from receiver's public key and sender's private key and random vector 256-bit length.
  Random vector is encrypted with ECIES and receiver's public key.
  Returns encrypted bytes array with a structure:
  [length-of-encrypted-random,ecies-encrypted(other-public-key, random-iv), gost-encrypted(one-time-secret,data)]"
  ^bytes
  [^BCECGOST3410_2012PrivateKey my-private-key ^BCECGOST3410_2012PublicKey other-public-key ^bytes data]
  (let [n                   (/ (s/-key-length other-public-key) 8) ;; get key length in bytes
        random-iv           (s/random-bytes 32)             ;; generate random 256 bits
        shared-secret-bytes (d/digest-2012-256
                              (condp = n                    ;; generate shared one-time secret key 256-bit length
                                32 (s/generate-shared-secret-256 my-private-key other-public-key random-iv)
                                64 (s/generate-shared-secret-512 my-private-key other-public-key random-iv)))
        secret-key          (e/byte-array->secret-key shared-secret-bytes)
        encrypted-data      (e/protect-bytes secret-key data) ;; encrypt data using one-time shared secret key
        cipher              (Cipher/getInstance "ECIES" "BC")
        _                   (.init ^Cipher cipher Cipher/ENCRYPT_MODE other-public-key)
        encrypted-random-iv (.doFinal cipher random-iv)     ;; encrypt random-iv using receiver's public key
        result-baos         (ByteArrayOutputStream.)]
    (.write result-baos (alength encrypted-random-iv))
    (.write result-baos ^bytes encrypted-random-iv)
    (.write result-baos ^bytes encrypted-data)
    (.toByteArray result-baos)))


(defn decrypt-bytes
  "Decrypt bytes using EC keys.
  Data will be decrypted with one-time secret key 256-bit length.
  One-time secret key is derived from sender's public key and receiver's private key and random vector 256-bit length.
  Random vector is decrypted with ECIES using receiver's private key.
  Returns plain data as bytes array if success or throws Exception if failure."
  ^bytes
  [^BCECGOST3410_2012PrivateKey my-private-key ^BCECGOST3410_2012PublicKey other-public-key ^bytes encrypted-data]
  (let [n                       (/ (s/-key-length other-public-key) 8) ;; get key length in bytes
        in                      (io/input-stream encrypted-data)
        encrypted-random-length (.read in)                  ;; read how many bytes is encrypted-random-iv
        encrypted-random-iv     (byte-array encrypted-random-length)
        _                       (when (< (.read in encrypted-random-iv) 117) ;; read encrypted-random-iv
                                  (throw (ex-info "Wrong encrypted header length" {})))
        cipher                  (Cipher/getInstance "ECIES" "BC")
        _                       (.init ^Cipher cipher Cipher/DECRYPT_MODE my-private-key)
        random-iv               (.doFinal cipher encrypted-random-iv) ;; decrypt random-iv with receiver's private key
        shared-secret-bytes     (d/digest-2012-256
                                  (condp = n                ;; generate shared one-time secret key 256-bit length
                                    32 (s/generate-shared-secret-256 my-private-key other-public-key random-iv)
                                    64 (s/generate-shared-secret-512 my-private-key other-public-key random-iv)))
        secret-key              (e/byte-array->secret-key shared-secret-bytes)]
    ;; decrypt data using shared one-time secret key
    (e/unprotect-bytes secret-key in)))


(defn encrypt-file
  "Encrypt file using EC keys.
  Data from `input-file` will be encrypted with one-time secret key 256-bit length and saved to `output-file`.
  One-time secret key is derived from receiver's public key and sender's private key and random vector 256-bit length.
  Random vector is encrypted with ECIES and receiver's public key.
  Returns encrypted file name `output-file`.
  Encrypted file has a structure:
  [length-of-encrypted-random,ecies-encrypted(other-public-key, random-iv), gost-encrypted(one-time-secret,data)]"
  ^bytes
  [^BCECGOST3410_2012PrivateKey my-private-key ^BCECGOST3410_2012PublicKey other-public-key ^String input-file ^String output-file]
  (let [n                   (/ (s/-key-length other-public-key) 8) ;; get key length in bytes
        random-iv           (s/random-bytes 32)             ;; generate random 256 bits
        shared-secret-bytes (d/digest-2012-256
                              (condp = n                    ;; generate shared one-time secret key 256-bit length
                                32 (s/generate-shared-secret-256 my-private-key other-public-key random-iv)
                                64 (s/generate-shared-secret-512 my-private-key other-public-key random-iv)))
        secret-key          (e/byte-array->secret-key shared-secret-bytes)
        out                 (io/output-stream output-file)
        cipher              (Cipher/getInstance "ECIES" "BC")
        _                   (.init ^Cipher cipher Cipher/ENCRYPT_MODE other-public-key)
        encrypted-random-iv (.doFinal cipher random-iv)] ;; encrypt random-iv using receiver's public key
    (.write out (alength encrypted-random-iv))
    (.write out ^bytes encrypted-random-iv)
    (.close out)
    (binding [e/*protect-file-append* true] (e/protect-file secret-key input-file output-file))
    output-file))


(defn decrypt-file
  "Decrypt file using EC keys.
  Data from `input-file`  will be decrypted with one-time secret key 256-bit length and saved to `output-file`.
  One-time secret key is derived from sender's public key and receiver's private key and random vector 256-bit length.
  Random vector is decrypted with ECIES using receiver's private key.
  Returns `output-file` with decrypted content if success or throws Exception if failure."
  ^bytes
  [^BCECGOST3410_2012PrivateKey my-private-key ^BCECGOST3410_2012PublicKey other-public-key ^String input-file ^String output-file]
  (let [n                       (/ (s/-key-length other-public-key) 8) ;; get key length in bytes
        in                      (io/input-stream input-file)
        encrypted-random-length (.read in)                  ;; read how many bytes is encrypted-random-iv
        encrypted-random-iv     (byte-array encrypted-random-length)
        _                       (when (< (.read in encrypted-random-iv) 117) ;; read encrypted-random-iv
                                  (throw (ex-info "Wrong encrypted header length" {})))
        cipher                  (Cipher/getInstance "ECIES" "BC")
        _                       (.init ^Cipher cipher Cipher/DECRYPT_MODE my-private-key)
        random-iv               (.doFinal cipher encrypted-random-iv) ;; decrypt random-iv with receiver's private key
        shared-secret-bytes     (d/digest-2012-256
                                  (condp = n                ;; generate shared one-time secret key 256-bit length
                                    32 (s/generate-shared-secret-256 my-private-key other-public-key random-iv)
                                    64 (s/generate-shared-secret-512 my-private-key other-public-key random-iv)))
        secret-key              (e/byte-array->secret-key shared-secret-bytes)]
    ;; decrypt data using shared one-time secret key
    (e/unprotect-file secret-key in output-file)))



