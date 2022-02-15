(ns org.rssys.gost.digest
  "GOST digest (hashing) functions"
  (:require
    [clojure.java.io :as io]
    [clojure.string :as string])
  (:import
    (java.security
      Security)
    (org.bouncycastle.crypto
      Digest)
    (org.bouncycastle.crypto.digests
      GOST3411Digest
      GOST3411_2012_256Digest
      GOST3411_2012_512Digest)
    (org.bouncycastle.crypto.macs
      HMac)
    (org.bouncycastle.crypto.params
      KeyParameter)
    (org.bouncycastle.jce.provider
      BouncyCastleProvider)))


;; See https://datatracker.ietf.org/doc/html/rfc4357#section-11.2
;; Sequence id-GostR3411-94-CryptoProParamSet
(def ^:const crypto-pro-digest-s-box
  [10 4 5 6 8 1 3 7 13 12 14 0 9 2 11 15
   5 15 4 0 2 13 11 9 1 7 6 3 12 14 10 8
   7 15 12 14 9 4 1 0 3 11 5 2 6 10 8 13
   4 10 7 12 0 15 2 8 14 1 6 5 13 11 9 3
   7 6 4 11 9 12 2 10 1 8 0 14 15 13 3 5
   7 6 2 4 13 9 15 0 10 1 5 11 8 14 12 3
   13 14 4 1 7 0 5 10 3 12 8 15 6 2 9 11
   1 3 10 9 5 11 4 15 8 6 7 14 13 0 2 12])


(defn -gost-3411
  "Returns GOST3411Digest class initialized with given S-box.
  By default, CryptoPro S-box params is used."
  ([]
    (GOST3411Digest. (byte-array crypto-pro-digest-s-box)))
  ([^bytes s-box]
    (GOST3411Digest. s-box)))



(defn digest-stream
  "Calculate digest for input stream.
  By default, GOST3411_2012_256Digest engine is used. See `digest-classes-map` for available digest engines.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream and auto closed after.
  Returns byte array with calculated digest."
  ^bytes
  [input & {:keys [close-streams? digest-class] :or
            {close-streams? true
             digest-class   (GOST3411_2012_256Digest.)}}]
  (Security/addProvider (BouncyCastleProvider.))
  (assert (instance? Digest digest-class) "Got wrong Digest class. Should be instance of ^Digest.")
  (assert (string/includes? (.getAlgorithmName digest-class) "GOST") "Should be instance of GOST digest class.")
  (let [in            (io/input-stream input)
        buf           (byte-array 1024)
        digest-buffer (byte-array (.getDigestSize digest-class))]
    (loop [n (.read in buf)]
      (if (<= n 0)
        (do (.doFinal digest-class digest-buffer 0) digest-buffer)
        (recur (do (.update digest-class buf 0 n) (.read in buf)))))
    (when close-streams? (.close in))
    digest-buffer))


(defn digest-3411-94
  "Calculate digest GOST3411-94 for input stream.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream.
  Returns 256 bit byte array."
  ^bytes
  [input & {:keys [close-streams?] :or {close-streams? true}}]
  (digest-stream input :digest-class (-gost-3411) :close-streams? close-streams?))


(defn digest-2012-256
  "Calculate digest GOST3411-2012-256 for input stream.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream.
  Returns 256 bit byte array."
  ^bytes
  [input & {:keys [close-streams?] :or {close-streams? true}}]
  (digest-stream input :digest-class (GOST3411_2012_256Digest.) :close-streams? close-streams?))


(defn digest-2012-512
  "Calculate digest GOST3411-2012-512 for input stream.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream.
  Returns 512 bit byte array."
  ^bytes
  [input & {:keys [close-streams?] :or {close-streams? true}}]
  (digest-stream input :digest-class (GOST3411_2012_512Digest.) :close-streams? close-streams?))


(defn hmac-stream
  "Calculate HMAC for input stream using `secret-key`.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream."
  ^bytes
  [input ^bytes secret-key & {:keys [close-streams? digest-class] :or
                              {close-streams? true
                               digest-class   (GOST3411_2012_256Digest.)}}]
  (Security/addProvider (BouncyCastleProvider.))
  (assert (instance? Digest digest-class) "Got wrong Digest class. Should be instance of ^Digest.")
  (assert (string/includes? (.getAlgorithmName digest-class) "GOST") "Should be instance of GOST digest class.")
  (let [in          (io/input-stream input)
        hmac-class  (HMac. digest-class)
        _           (when (< (alength secret-key) 32)
                      (throw (ex-info (format "Seed bytes should be %s+ bytes length" 32)
                               {:seed-bytes-length (alength secret-key)})))
        _           (.init hmac-class (KeyParameter. secret-key))
        buf         (byte-array 1024)
        hmac-buffer (byte-array (.getMacSize hmac-class))]
    (loop [n (.read in buf)]
      (if (<= n 0)
        (do (.doFinal hmac-class hmac-buffer 0) hmac-buffer)
        (recur (do (.update hmac-class buf 0 n) (.read in buf)))))
    (when close-streams? (.close in))
    hmac-buffer))


(defn hmac-3411-94
  "Calculate HMAC GOST3411-94 using `secret-key` for input stream.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream.
  Returns 256 bit byte array."
  ^bytes
  [input ^bytes secret-key & {:keys [close-streams?] :or {close-streams? true}}]
  (hmac-stream input secret-key :digest-class (-gost-3411) :close-streams? close-streams?))


(defn hmac-2012-256
  "Calculate HMAC GOST3411-2012-256 using `secret-key` for input stream.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream.
  Returns 256 bit byte array."
  ^bytes
  [input ^bytes secret-key & {:keys [close-streams?] :or {close-streams? true}}]
  (hmac-stream input secret-key :digest-class (GOST3411_2012_256Digest.) :close-streams? close-streams?))


(defn hmac-2012-512
  "Calculate HMAC GOST3411-2012-512 using `secret-key` for input stream.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream.
  Returns 512 bit byte array."
  ^bytes
  [input ^bytes secret-key & {:keys [close-streams?] :or {close-streams? true}}]
  (hmac-stream input secret-key :digest-class (GOST3411_2012_512Digest.) :close-streams? close-streams?))

