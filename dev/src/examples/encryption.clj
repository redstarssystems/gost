(ns examples.encryption
  (:require
    [org.rssys.gost.encrypt :as e]))


;; Generate secret key for GOST3412-2015.
;; This will return 256-bit random secret key as a SecretKeySpec object.
;; Algorithm is set GOST3412-2015
(def secret-key-2015 (e/generate-secret-key))
(e/algo-name secret-key-2015) ;; => GOST3412-2015

;; Generate secret key GOST28147-89
;; This will return 256-bit random secret key as a SecretKeySpec object.
;; Algorithm is set GOST28147
(def secret-key-89 (e/generate-secret-key e/gost28147))
(e/algo-name secret-key-89) ;; => GOST28147

;; To convert SecretKeySpec to byte array
(e/secret-key->byte-array secret-key-2015) ;; => [B
;; [-38, -86, 71, -42, -69, 73, -33, 53, 72, 80, 38, 26, 57, 69, -114, -1,
;; -119, 13, 113, -84, -31, 54, -128, 114, -79, -55, 85, 126, 105, -96,
;; -37, -128]

;; To convert byte array to SecretKeySpec
(e/byte-array->secret-key (byte-array [-38, -86, 71, -42, -69, 73, -33, 53, 72, 80, 38, 26, 57, 69, -114, -1,
                                       -119, 13, 113, -84, -31, 54, -128, 114, -79, -55, 85, 126, 105, -96,
                                       -37, -128])) ;; => #object[javax.crypto.spec.SecretKeySpec

;; We can generate secret key bytes from password.
;; This function always return the same bytes value from the same String password.
;; By default, it uses min 10000 iterations of PBKDF2WITHHMACGOST3411 algorithm, recommended by NIST
(e/generate-secret-bytes-from-password "qwerty12345") ;; => [B
;;[-113, 62, 87, -90, 116, -44, -20, -98, 4, -108, 77, -59, -22, 25, -73,
;; 20, -31, 62, -86, 19, 103, 81, -64, 32, 74, 81, -32, -97, -78, 123,
;; -82, -70]

;; To convert it to SecretKeySpec
(e/byte-array->secret-key
  (e/generate-secret-bytes-from-password "qwerty12345")) ;; => #object[javax.crypto.spec.SecretKeySpec

;;;;;;;;;;;;;;;
;; High-level functions
;;;;;;;;;;;;;;;

(def message "This text has length = 32 bytes.")


;; To encrypt byte array (any binary content) in a most secured way just use `protect-bytes` function.
;; Encryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; This function calculates Mac for plain data, then
;; compress plain data to hide information structure, then
;; encrypts data and Mac in CFB mode with always random IV.
;; Encrypted bytes from the same message and same key are always different!
(def encrypted-message (e/protect-bytes secret-key-2015 (.getBytes message))) ;; Returns bytes array with structure:
;; [random(IV), encrypted(Mac), encrypted(compressed-data)]

;; To decrypt and restore plain text just use `unprotect-bytes` function.
;; Decryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; This function decrypt Mac and data, then
;; decompress data, then calculate Mac for decompressed data, then
;; compare Mac from message and Mac calculated.
;; If Macs are the same then return plain data, otherwise throw an Exception.
(def decrypted-message (e/unprotect-bytes secret-key-2015 encrypted-message))

(= message (String. ^bytes decrypted-message)) ;; => true

;; To encrypt file (any binary content) in a most secured way just use `protect-file` function.
;; Encryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; This function calculates Mac for plain file, then
;; compress plain file to hide information structure, then
;; encrypts data and Mac in CFB mode with always random IV.
;; Encrypted bytes from the same message and same key are always different!
(e/protect-file secret-key-2015 "dev/src/examples/plain32.txt" "target/plain32.enc") ;; Encrypted file has structure:
;; random(IV), encrypted(Mac), encrypted(compressed-data).

;; To decrypt file just use `unprotect-file` function.
;; Decryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; This function decrypt Mac and data, then
;; decompress data in file, then calculate Mac for decompressed data, then
;; compare Mac from message and Mac calculated.
;; If Macs are the same then return output file name as String, otherwise throw an Exception.
(e/unprotect-file secret-key-2015 "target/plain32.enc" "target/plain32.txt")

(= (slurp "dev/src/examples/plain32.txt") (slurp "target/plain32.txt")) ;; => true

;; To calculate Mac for file (any binary file) use `mac-stream` function.
;; Encryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; Mac value from the same data and same SecretKeySpec is always the same.
(e/mac-stream secret-key-2015 "dev/src/examples/plain32.txt") ;; => [B
;; [-111, 125, 10, -34, -109, -109, 41, 115, 81, 61, -90, -80, 16, 71, -108, 91]

;; To calculate Mac for byte array (any binary file) use the same `mac-stream` function.
;; Encryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; Mac value from the same data and same SecretKeySpec is always the same.
(e/mac-stream secret-key-2015 (.getBytes message)) ;; => [B
;; [-111, 125, 10, -34, -109, -109, 41, 115, 81, 61, -90, -80, 16, 71, -108, 91]


