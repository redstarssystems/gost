(ns org.rssys.gost.symmetric
  "Encryption / decryption functions using GOST"
  (:require
    [clojure.java.io :as io]
    [clojure.set]
    [org.rssys.gost.common :as common])
  (:import
    (clojure.lang
      Keyword)
    (java.io
      ByteArrayOutputStream
      DataInputStream)
    (java.security
      SecureRandom
      Security)
    (java.security.spec
      AlgorithmParameterSpec)
    (java.util.zip
      Deflater
      DeflaterOutputStream
      InflaterOutputStream)
    (javax.crypto
      Cipher
      CipherInputStream
      CipherOutputStream
      KeyGenerator
      Mac
      SecretKeyFactory)
    (javax.crypto.spec
      IvParameterSpec
      PBEKeySpec
      SecretKeySpec)
    (org.bouncycastle.asn1
      ASN1ObjectIdentifier)
    (org.bouncycastle.crypto.macs
      GOST28147Mac)
    (org.bouncycastle.crypto.params
      KeyParameter
      ParametersWithSBox)
    (org.bouncycastle.jcajce.spec
      GOST28147ParameterSpec)
    (org.bouncycastle.jce.provider
      BouncyCastleProvider)))


;;;;;;;
;; Low level functions and constants
;;;;;;;

(def ^:const gost28147 "GOST28147")
(def ^:const gost3412-2015 "GOST3412-2015")

(def ^:const iv-length-8 8)
(def ^:const iv-length-16 16)

(def ^:const mac-length-gost28147 4)
(def ^:const mac-length-gost3412-2015 16)


(def ^{:doc "GOST symmetric algorithms"}
  allowed-algo-names-set
  #{gost28147 gost3412-2015})


(def ^{:doc "Secret key length in bytes" :const true}
  secret-key-length-bytes
  32)


(def ^{:doc "Secret key length in bits" :const true}
  secret-key-length-bits
  256)


(def ^:dynamic *password-unique-symbols-min-count*
  "How many unique symbols in password should be"
  5)


(def ^:dynamic *secret-key-unique-bytes-min-count*
  "How many unique bytes in secret key should be"
  7)


;; https://datatracker.ietf.org/doc/html/rfc4357
;; id-Gost28147-89-CryptoPro-A-ParamSet
(def ^:const s-box-crypto-pro-a
  [9 6 3 2 8 11 1 7 10 4 14 15 12 0 13 5
   3 7 14 9 8 10 15 0 5 2 6 12 11 4 13 1
   14 4 6 2 11 3 13 8 12 15 5 10 0 7 1 9
   14 7 10 12 13 1 3 9 0 2 11 4 15 8 5 6
   11 5 1 9 8 13 15 0 14 4 2 3 12 7 10 6
   3 10 13 12 1 2 0 11 7 5 9 4 8 15 14 6
   1 13 2 9 7 10 6 0 8 12 4 5 15 3 11 14
   11 10 15 5 0 12 14 8 6 2 3 9 1 7 13 4])


(defn- check-algo-name
  [^String algo-name]
  (when (not (allowed-algo-names-set algo-name))
    (throw
      (ex-info
        (str "Allowed values for algorithm are: " (apply str (interpose ", " allowed-algo-names-set)))
        {:algo-name algo-name}))))


(defn algo-name
  "Get algorithm name for given crypto primitive. Returns String name."
  [cp]
  (.getAlgorithm cp))


(defn count-unique
  "Count unique elements in a byte array."
  [^bytes b-array]
  (count (into #{} b-array)))


(def allowed-cipher-modes-map
  {:cfb-mode 0
   :ctr-mode 1
   :cbc-mode 2})


(def allowed-cipher-modes-set (into #{} (keys allowed-cipher-modes-map)))


;;;;;;;;;;
;; Core functions
;;;;;;;;;

(defn generate-secret-key
  "Generate secret key using SecureRandom.
  By default, it generates Secret key for GOST3412-2015.
  Params:
    * `algo-name` - String, allowed values \"GOST28147\" or \"GOST3412-2015\" (default)
  Returns ^SecretKeySpec key"
  ^SecretKeySpec
  ([]
    (generate-secret-key gost3412-2015))
  ([^String algo-name]
    (Security/addProvider (BouncyCastleProvider.))
    (check-algo-name algo-name)
    (let [key-generator (KeyGenerator/getInstance algo-name "BC")
          _             (.init key-generator (SecureRandom.))]
      (.generateKey key-generator))))


(defn generate-secret-bytes-from-password
  "Generate secret key bytes using given password.
  Returns secret key bytes array length of 32 bytes."
  ([^String password-string]
    (generate-secret-bytes-from-password password-string 10000))
  ;; min 10000 recommended by NIST

  ([^String password-string ^Long iter-count]
    (Security/addProvider (BouncyCastleProvider.))
    (when (< (count-unique (.getBytes password-string)) *password-unique-symbols-min-count*)
      (throw (ex-info "Byte array contains a weak password" {})))
    (let [salt-bytes     (.getBytes "org.rssys.password.salt.string!!")
          secret-factory (SecretKeyFactory/getInstance "PBKDF2WITHHMACGOST3411" "BC")
          key-spec       (PBEKeySpec. (.toCharArray password-string) salt-bytes iter-count secret-key-length-bits)
          secret-key     (.generateSecret secret-factory key-spec)]
      (.getEncoded secret-key))))


(defn secret-key->byte-array
  "Convert ^SecretKeySpec to a byte array"
  [^SecretKeySpec k]
  (.getEncoded k))


(defn byte-array->secret-key
  "Create secret key from the byte array.
  Returns ^SecretKeySpec.
  This function prevents the loading of weak keys.
  Params:
    * `sk-bytes` - byte array 32 bytes length
    * `algo` - allowed values \"GOST28147\" or \"GOST3412-2015\" (default)"
  ([^bytes sk-bytes]
    (byte-array->secret-key sk-bytes gost3412-2015))
  ([^bytes sk-bytes ^String algo-name]
    (check-algo-name algo-name)
    (cond
      (not= secret-key-length-bytes (alength sk-bytes)) (throw (ex-info "Byte array length should be 32 bytes" {}))
      (< (count-unique sk-bytes) *secret-key-unique-bytes-min-count*) (throw (ex-info "Byte array contains a weak key" {}))
      :else (SecretKeySpec. sk-bytes algo-name))))



(defn init-cipher-mode
  "Init cipher mode. Returns ^Cipher.
  Allowed cipher modes: :cfb-mode :ctr-mode :cbc-mode"
  [^String algo-name ^Keyword cipher-mode]
  (Security/addProvider (BouncyCastleProvider.))
  (check-algo-name algo-name)
  (let [mode   ^String (condp = algo-name
                         gost3412-2015 (condp = cipher-mode
                                         :cfb-mode "GOST3412-2015/CFB/NoPadding"
                                         :ctr-mode "GOST3412-2015/CTR/NoPadding"
                                         :cbc-mode "GOST3412-2015/CBC/PKCS7Padding"
                                         (throw (ex-info (str "Unknown cipher mode. Allowed values: "
                                                           (apply str (interpose ", " allowed-cipher-modes-set))) {:cipher-mode cipher-mode})))
                         gost28147 (condp = cipher-mode
                                     :cfb-mode "GOST28147/CFB/NoPadding"
                                     :ctr-mode "GOST28147/CTR/NoPadding"
                                     :cbc-mode "GOST28147/CBC/PKCS7Padding"
                                     (throw (ex-info (str "Unknown cipher mode. Allowed values: "
                                                       (apply str (interpose ", " allowed-cipher-modes-set))) {:cipher-mode cipher-mode}))))
        cipher (Cipher/getInstance mode "BC")]
    cipher))


(defn new-iv-8
  "Create new random init vector using SecureRandom.
  Returns byte array 8 bytes length with random data."
  []
  (let [iv-array (byte-array iv-length-8)]
    (.nextBytes (SecureRandom.) iv-array)
    iv-array))


(defn new-iv-16
  "Create new random init vector using SecureRandom.
  Returns byte array 16 bytes length with random data."
  []
  (let [iv-array (byte-array iv-length-16)]
    (.nextBytes (SecureRandom.) iv-array)
    iv-array))


(defn new-iv
  "Create new random init vector using SecureRandom for given algorithm.
  Allowed cipher modes: :cfb-mode :ctr-mode :cbc-mode
  Returns byte array appropriate length for algorithm with random data."
  [^String algo-name ^Keyword cipher-mode]
  (cond
    (= :ctr-mode cipher-mode) (new-iv-8)                    ;; CTR mode for GOST3412-2015 requires 8 bytes
    (= algo-name gost28147) (new-iv-8)
    (= algo-name gost3412-2015) (new-iv-16)))


(defn iv-length-by-algo-mode
  "Return IV length by algo and cipher mode"
  [^String algo-name ^Keyword cipher-mode]
  (cond
    (= :ctr-mode cipher-mode) iv-length-8                   ;; CTR mode for GOST3412-2015 requires 8 bytes
    (= algo-name gost28147) iv-length-8
    (= algo-name gost3412-2015) iv-length-16))


(defn mac-length-by-algo
  "Return Mac length by algo mode"
  [^String algo-name]
  (cond
    (= algo-name gost28147) mac-length-gost28147
    (= algo-name gost3412-2015) mac-length-gost3412-2015))


(defn init-gost-named-params
  "Init algorithm using given init vector and S-Box named parameters.
  Returns ^AlgorithmParameterSpec - initialized GOST algorithm parameters.
  Allowed param names for GOST28147-89:
  \"E-A\"     - Gost28147_89_CryptoPro_A_ParamSet (most used)
  \"E-B\"     - Gost28147_89_CryptoPro_B_ParamSet (most used)
  \"E-C\"     - Gost28147_89_CryptoPro_C_ParamSet
  \"E-D\"     - Gost28147_89_CryptoPro_D_ParamSet
  \"Param-Z\" - tc26_gost_28147_param_Z
  \"Default\" - S-Boxes from 'Applied cryptography' book
  \"E-Test\"  - test S-Box, for tests ONLY

  For GOST3412-2015 - param names are ignored."
  ^AlgorithmParameterSpec
  [^String algo-name ^bytes iv ^String param-name]
  (condp = algo-name
    gost28147 (GOST28147ParameterSpec. param-name iv)
    gost3412-2015 (IvParameterSpec. iv)))


(defn init-gost-oid-params
  "Init algorithm using given init vector and S-Box OID parameters.
  Returns ^AlgorithmParameterSpec - initialized GOST algorithm parameters.
   For GOST3412-2015 - oid-name is ignored."
  ^AlgorithmParameterSpec
  [^String algo-name ^bytes iv ^ASN1ObjectIdentifier oid-name]
  (condp = algo-name
    gost28147 (GOST28147ParameterSpec. oid-name iv)
    gost3412-2015 (IvParameterSpec. iv)))


(defn init-gost-sbox-binary-params
  "Init algorithm using given init vector and S-Box binary array.
  Returns ^AlgorithmParameterSpec - initialized GOST algorithm parameters.
   For GOST3412-2015 - s-box bytes are ignored."
  ^AlgorithmParameterSpec
  [^String algo-name ^bytes iv ^bytes s-box]
  (condp = algo-name
    gost28147 (GOST28147ParameterSpec. s-box iv)
    gost3412-2015 (IvParameterSpec. iv)))


(defn encrypt-bytes
  "Encrypt plain data using given initialized ^Cipher in encryption mode.
   Returns encrypted bytes array."
  [^Cipher cipher ^bytes plain-bytes]
  (.doFinal cipher plain-bytes))


(defn decrypt-bytes
  "Decrypt data using given initialized ^Cipher in decryption mode.
  Returns plain data bytes array."
  [^Cipher cipher ^bytes encrypted-bytes]
  (.doFinal cipher encrypted-bytes))


(defn mac-28147
  "Calculate MAC for plain data using secret-key and GOST28147 algorithm.
  Returns byte array with calculated MAC."
  ([^SecretKeySpec secret-key ^bytes plain-data]
    (mac-28147 secret-key plain-data (byte-array s-box-crypto-pro-a)))
  ;; by default we use CryptoPro_A_ParamSet

  ([^SecretKeySpec secret-key ^bytes plain-data ^bytes s-box]
    (Security/addProvider (BouncyCastleProvider.))
    (let [params (ParametersWithSBox. (KeyParameter. (secret-key->byte-array secret-key)) s-box)
          mac    (GOST28147Mac.)
          _      (.init mac params)
          buffer (byte-array mac-length-gost28147)]
      (.update mac plain-data 0 (alength plain-data))
      (.doFinal mac buffer 0)
      buffer)))


(defn mac-3412
  "Calculate MAC for plain data using secret-key and GOST3412-2015 algorithm.
  Returns byte array with calculated MAC."
  [^SecretKeySpec secret-key ^bytes plain-data]
  (Security/addProvider (BouncyCastleProvider.))
  (let [mac (Mac/getInstance "GOST3412MAC" "BC")
        _   (.init mac secret-key)]
    (.doFinal mac plain-data)))


(defn mac-bytes
  "Calculate MAC for plain data bytes array using secret-key. Algorithm is set inside ^SecretKeySpec.
  Returns byte array with calculated MAC."
  ([^SecretKeySpec secret-key ^bytes plain-data]
    (mac-bytes secret-key plain-data (byte-array s-box-crypto-pro-a)))
  ([^SecretKeySpec secret-key ^bytes plain-data ^bytes s-box]
    (condp = (algo-name secret-key)
      gost3412-2015 (mac-3412 secret-key plain-data)
      gost28147 (mac-28147 secret-key plain-data s-box))))


(defn mac-3412-stream
  "Calculate MAC for input stream using secret-key and GOST3412. Algorithm is set inside ^SecretKeySpec.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream and auto closed after.
  Returns byte array with calculated MAC."
  [^SecretKeySpec secret-key input & {:keys [close-streams?] :or {close-streams? true}}]
  (Security/addProvider (BouncyCastleProvider.))
  (let [in     (io/input-stream input)
        mac    (Mac/getInstance "GOST3412MAC" "BC")
        _      (.init mac secret-key)
        buffer (byte-array 1024)
        result (loop [n (.read in buffer)]
                 (if (<= n 0)
                   (.doFinal mac)
                   (recur (do (.update mac buffer 0 n) (.read in buffer)))))]
    (when close-streams? (.close in))
    result))


(defn mac-28147-stream
  "Calculate MAC for input stream using secret-key and GOST28147. Algorithm is set inside ^SecretKeySpec.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream and auto closed after.
  Returns byte array with calculated MAC."
  ([^SecretKeySpec secret-key input]
    (mac-28147-stream secret-key input (byte-array s-box-crypto-pro-a)))
  ;; by default we use CryptoPro_A_ParamSet
  ([^SecretKeySpec secret-key input ^bytes s-box & {:keys [close-streams?] :or {close-streams? true}}]
    (Security/addProvider (BouncyCastleProvider.))
    (let [in         (io/input-stream input)
          params     (ParametersWithSBox. (KeyParameter. (secret-key->byte-array secret-key)) s-box)
          mac        (GOST28147Mac.)
          _          (.init mac params)
          buffer     (byte-array 1024)
          mac-buffer (byte-array mac-length-gost28147)
          result     (loop [n (.read in buffer)]
                       (if (<= n 0)
                         (do
                           (.doFinal mac mac-buffer 0)
                           mac-buffer)
                         (recur (do (.update mac buffer 0 n) (.read in buffer)))))]
      (when close-streams? (.close in))
      result)))


(defn mac-stream
  "Calculate MAC for plain data stream using secret-key. Algorithm is set inside ^SecretKeySpec.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream and auto closed after.
  Returns byte array with calculated MAC."
  ([^SecretKeySpec secret-key input]
    (mac-stream secret-key input (byte-array s-box-crypto-pro-a)))
  ([^SecretKeySpec secret-key input ^bytes s-box]
    (condp = (algo-name secret-key)
      gost3412-2015 (mac-3412-stream secret-key input)
      gost28147 (mac-28147-stream secret-key input s-box))))


(defn compress-bytes
  "Compress plain bytes array using Deflate Zip.
  Returns: byte array of compressed data."
  ^bytes
  [^bytes plain-bytes]
  (with-open [byte-stream (ByteArrayOutputStream.)
              zip-stream  (DeflaterOutputStream. byte-stream (Deflater. Deflater/BEST_COMPRESSION))]
    (.write zip-stream plain-bytes)
    (.close zip-stream)
    (.toByteArray byte-stream)))


(defn decompress-bytes
  "Decompress bytes using Deflate Zip.
  Returns: byte array of plain data."
  ^bytes
  [^bytes compressed-bytes]
  (with-open [byte-stream (ByteArrayOutputStream.)
              zip-stream  (InflaterOutputStream. byte-stream)]
    (.write zip-stream compressed-bytes)
    (.toByteArray byte-stream)))


(defn encrypt-stream
  "Encrypt given streaming input and write encrypted data to streaming output,
  using given initialized ^Cipher in encryption mode.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream and auto closed after.
  Output should be  File, URI, URL, Socket, or filename as String  which  will be
  coerced to BufferedOutputStream and auto closed after."
  [^Cipher cipher input output & {:keys [close-streams?] :or {close-streams? true}}]
  (let [in            (io/input-stream input)
        out           (io/output-stream output)
        cipher-stream (CipherOutputStream. out cipher)]
    (io/copy in cipher-stream)
    (when close-streams? (.close cipher-stream) (.close out) (.close in))))


(defn decrypt-stream
  "Decrypt given streaming input and write plain data to streaming output,
  using given initialized ^Cipher in decryption mode.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream and auto closed after.
  Output should be File, URI, URL, Socket, or filename as String which will be
  coerced to BufferedOutputStream and auto closed after."
  [^Cipher cipher input output & {:keys [close-streams?] :or {close-streams? true}}]
  (let [in            (io/input-stream input)
        out           (io/output-stream output)
        cipher-stream (CipherInputStream. in cipher)
        data-stream   (DataInputStream. cipher-stream)]
    (io/copy data-stream out)
    (when close-streams? (.close data-stream) (.close cipher-stream) (.close out) (.close in))))


(defn compress-stream
  "Compress given streaming input and write compressed bytes to streaming output.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream and auto closed after.
  Output should be  File, URI, URL, Socket, or filename as String  which  will be
  coerced to BufferedOutputStream and auto closed after."
  [input output & {:keys [close-streams?] :or {close-streams? true}}]
  (let [in         (io/input-stream input)
        out        (io/output-stream output)
        zip-stream (DeflaterOutputStream. out (Deflater. Deflater/BEST_COMPRESSION))]
    (io/copy in zip-stream)
    (when close-streams? (.close zip-stream) (.close out) (.close in))))


(defn decompress-stream
  "Decompress given streaming input and write uncompressed bytes to streaming output.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream and auto closed after.
  Output should be  File, URI, URL, Socket, or filename as String  which  will be
  coerced to BufferedOutputStream and auto closed after."
  [input output & {:keys [close-streams?] :or {close-streams? true}}]
  (let [in         (io/input-stream input)
        out        (io/output-stream output)
        zip-stream (InflaterOutputStream. out)]
    (io/copy in zip-stream)
    (when close-streams? (.close zip-stream) (.close out) (.close in))))


(defn new-encryption-cipher
  "Create new cipher for encryption. Algorithm is set inside SecretKeySpec.
   Allowed cipher modes: :cfb-mode :ctr-mode :cbc-mode
   Returns ^Cipher."
  ([^SecretKeySpec secret-key ^Keyword cipher-mode]
    (let [iv (new-iv (algo-name secret-key) cipher-mode)]    ;; for every message we should have unique IV
      ;; By default, we use CryptoPro_A_ParamSet for GOST28147-89, but for GOST 3412-2015 this param set is ignored.
      (new-encryption-cipher secret-key cipher-mode
        (init-gost-sbox-binary-params (algo-name secret-key) iv (byte-array s-box-crypto-pro-a)))))
  ([^SecretKeySpec secret-key ^Keyword cipher-mode ^AlgorithmParameterSpec algo-params]
    (let [cipher (init-cipher-mode (algo-name secret-key) cipher-mode)]
      (.init cipher Cipher/ENCRYPT_MODE secret-key algo-params)
      cipher)))


(defn new-decryption-cipher
  "Create new cipher for decryption. Algorithm is set inside SecretKeySpec.
   Appropriate IV for decryption should be set inside ^AlgorithmParameterSpec
   Allowed cipher modes: :cfb-mode :ctr-mode :cbc-mode
   Returns ^Cipher."
  [^SecretKeySpec secret-key ^Keyword cipher-mode ^AlgorithmParameterSpec algo-params]
  (let [cipher (init-cipher-mode (algo-name secret-key) cipher-mode)]
    (.init cipher Cipher/DECRYPT_MODE secret-key algo-params)
    cipher))


(defn compress-and-encrypt-stream
  "Compress and then encrypt given streaming input and write encrypted data to streaming output,
  using given initialized ^Cipher in encryption mode.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream and auto closed after.
  Output should be  File, URI, URL, Socket, or filename as String  which  will be
  coerced to BufferedOutputStream and auto closed after."
  [^Cipher cipher input output & {:keys [close-streams?] :or {close-streams? true}}]
  (let [out           (io/output-stream output)
        cipher-stream (CipherOutputStream. out cipher)]
    (compress-stream input cipher-stream :close-streams close-streams?)
    (when close-streams? (.close cipher-stream) (.close out))))


(defn decrypt-and-decompress-stream
  "Decrypt and then decompress given streaming input and write plain data to streaming output,
  using given initialized ^Cipher in decryption mode.
  As input may be: File, URI, URL, Socket, byte array, or filename as String which will be
  coerced to BufferedInputStream and auto closed after.
  Output should be  File, URI, URL, Socket, or filename as String  which  will be
  coerced to BufferedOutputStream and auto closed after."
  [^Cipher cipher input output & {:keys [close-streams?] :or {close-streams? true}}]
  (let [out        (io/output-stream output)
        zip-stream (InflaterOutputStream. out)]
    (decrypt-stream cipher input zip-stream :close-streams close-streams?)
    (when close-streams? (.close zip-stream) (.close out))))


(defn protect-bytes
  "Encrypt, compress, calculate MAC for plain data.
  IV is always random. Encryption mode is CFB.
  For 28147-89 default s-box is id-Gost28147-89-CryptoPro-A-ParamSet. For GOST3412-2015 s-box is ignored.
  Returns bytes array with structure: [IV, encrypted(Mac), encrypted(compressed-data)]"
  ([^SecretKeySpec secret-key ^bytes data]
    (let [iv (new-iv (algo-name secret-key) :cfb-mode)]
      (protect-bytes secret-key data (init-gost-sbox-binary-params (algo-name secret-key) iv (byte-array s-box-crypto-pro-a)))))
  ([^SecretKeySpec secret-key ^bytes data ^AlgorithmParameterSpec algo-spec]
    (if (or (nil? data) (= 0 (alength data)))
      (throw (ex-info "Empty byte array or nil is not allowed" {}))
      (let [cipher        (new-encryption-cipher secret-key :cfb-mode algo-spec)
            algo-name-string (algo-name secret-key)
            baos-data     (ByteArrayOutputStream.)
            mac           (cond
                            (= algo-name-string gost28147) (mac-stream secret-key data (.getSBox algo-spec))
                            (= algo-name-string gost3412-2015) (mac-stream secret-key data))
            encrypted-mac (encrypt-bytes cipher mac)
            result-baos   (ByteArrayOutputStream.)]
        (compress-and-encrypt-stream cipher data baos-data)
        (.write result-baos ^bytes (.getIV cipher))
        (.write result-baos ^bytes encrypted-mac)
        (.write result-baos ^bytes (.toByteArray baos-data))
        (.toByteArray result-baos)))))


(defn unprotect-bytes
  "Decrypt, decompress input data bytes, verify MAC for decrypted plain data.
  For 28147-89 default s-box is id-Gost28147-89-CryptoPro-A-ParamSet. For GOST3412-2015 s-box is ignored.
  Returns plain data as bytes array if success or throws Exception if failure."
  [^SecretKeySpec secret-key ^bytes input & {:keys [s-box] :or {s-box (byte-array s-box-crypto-pro-a)}}]
  (let [in               (io/input-stream input)
        algo-name-string (algo-name secret-key)
        cipher-mode      :cfb-mode
        iv               (byte-array (iv-length-by-algo-mode algo-name-string cipher-mode))
        _                (.read in iv)
        mac-buffer       (byte-array (mac-length-by-algo algo-name-string))
        _                (.read in mac-buffer)
        cipher           (new-decryption-cipher secret-key cipher-mode (init-gost-sbox-binary-params algo-name-string iv s-box))
        mac              (decrypt-bytes cipher mac-buffer)
        baos-data        (ByteArrayOutputStream.)
        _                (decrypt-and-decompress-stream cipher in baos-data)
        decrypted-data   (.toByteArray baos-data)
        new-mac          (mac-stream secret-key decrypted-data s-box)]
    (when (not= (into [] new-mac) (into [] mac))
      (throw (ex-info "Decrypted data is corrupted: Mac codes are different"
               {:mac     (common/bytes-to-hex mac)
                :new-mac (common/bytes-to-hex new-mac)})))
    (.close in)
    decrypted-data))


(defn protect-file
  "Encrypt, compress, calculate MAC for plain data from `input-filename`.
  IV is always random. Encryption mode is CFB.
  For 28147-89 default s-box is id-Gost28147-89-CryptoPro-A-ParamSet. For GOST3412-2015 s-box is ignored.
  Save encrypted data to `output-filename` (create or overwrite it) with structure: [IV, encrypted(Mac), encrypted(compressed-data)].
  Returns ^String value of `output-filename` if success or throw Exception if error."
  ([^SecretKeySpec secret-key ^String input-filename ^String output-filename]
    (let [iv (new-iv (algo-name secret-key) :cfb-mode)]
      (protect-file secret-key input-filename output-filename
        (init-gost-sbox-binary-params (algo-name secret-key) iv (byte-array s-box-crypto-pro-a)))))
  ([^SecretKeySpec secret-key ^String input-filename ^String output-filename ^AlgorithmParameterSpec algo-spec]
    (when (or (not (.exists (io/file input-filename))) (zero? (.length (io/file input-filename))))
      (throw (ex-info "File not exist or empty" {:input-file input-filename})))
    (let [cipher           (new-encryption-cipher secret-key :cfb-mode algo-spec)
          algo-name-string (algo-name secret-key)
          in-mac           (io/input-stream input-filename)
          mac              (cond
                             (= algo-name-string gost28147) (mac-stream secret-key in-mac (.getSBox algo-spec))
                             (= algo-name-string gost3412-2015) (mac-stream secret-key in-mac))
          _                (.close in-mac)
          encrypted-mac    (encrypt-bytes cipher mac)
          in               (io/input-stream input-filename)
          out              (io/output-stream output-filename)]
      (.write out ^bytes (.getIV cipher))
      (.write out ^bytes encrypted-mac)
      (compress-and-encrypt-stream cipher in out :close-streams false)
      (.close in)
      (.close out)
      output-filename)))


(defn unprotect-file
  "Decrypt, decompress content of `input-filename`, verify MAC for plain data.
  Save plain data to `output-filename` file (create or overwrite it).
  For 28147-89 default s-box is id-Gost28147-89-CryptoPro-A-ParamSet. For GOST3412-2015 s-box is ignored.
  Returns ^String value of `output-filename` if success or throw Exception if error."
  [^SecretKeySpec secret-key ^String input-filename ^String output-filename & {:keys [s-box] :or {s-box (byte-array s-box-crypto-pro-a)}}]
  (when (or (not (.exists (io/file input-filename))) (zero? (.length (io/file input-filename))))
    (throw (ex-info "File not exist or empty" {:input-file input-filename})))
  (let [in               (io/input-stream input-filename)
        algo-name-string (algo-name secret-key)
        cipher-mode      :cfb-mode
        iv               (byte-array (iv-length-by-algo-mode algo-name-string cipher-mode))
        _                (.read in iv)
        mac-buffer       (byte-array (mac-length-by-algo algo-name-string))
        _                (.read in mac-buffer)
        cipher           (new-decryption-cipher secret-key cipher-mode (init-gost-sbox-binary-params algo-name-string iv s-box))
        mac              (decrypt-bytes cipher mac-buffer)
        out              (io/output-stream output-filename)
        _                (decrypt-and-decompress-stream cipher in out :close-streams false)
        _                (.close out)
        new-mac          (mac-stream secret-key (io/input-stream output-filename) s-box)]
    (when (not= (into [] new-mac) (into [] mac))
      (throw (ex-info "Decrypted data is corrupted: Mac codes are different"
               {:mac     (common/bytes-to-hex mac)
                :new-mac (common/bytes-to-hex new-mac)})))
    (.close in)
    output-filename))


