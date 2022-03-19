(ns org.rssys.gost.common
  "Common functions"
  (:import
    (javax.crypto
      Cipher)
    (org.bouncycastle.util.encoders
      Base64
      Hex)))


(defn jce-unlimited?
  "Check if JCA/JCE has unlimited cryptography strength.
  Call this function to check JVM runtime before use of any crypto functions."
  []
  (if (= 2147483647 (Cipher/getMaxAllowedKeyLength "AES"))
    true
    false))


(defn bytes-to-hex
  "Convert bytes array to hex String."
  [b]
  (Hex/toHexString b))


(defn hex-to-bytes
  "Convert hex String to bytes array"
  [^String s]
  (Hex/decode s))


(defn base64-encode
  "Convert bytes to Base64 String.
  Returns ^String."
  ^String
  [^bytes data]
  (String. (Base64/encode data)))


(defn base64-decode
  "Convert Base64 String to data.
  Returns ^bytes."
  ^bytes
  [^String base64-str]
  (Base64/decode base64-str))

