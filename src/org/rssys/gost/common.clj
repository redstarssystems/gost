(ns org.rssys.gost.common
  "Common functions"
  (:import
    (javax.crypto
      Cipher)
    (org.bouncycastle.util.encoders
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
