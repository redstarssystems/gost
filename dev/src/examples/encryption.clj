(ns examples.encryption
  (:require
    [org.rssys.gost.encrypt :as e]))


;; To generate a secret key for the GOST3412-2015 use `generate-secret-key` function.
;; This will return a 256-bit random secret key as a SecretKeySpec object.
;; The algorithm is set to GOST3412-2015
(def secret-key-2015 (e/generate-secret-key))
(e/algo-name secret-key-2015) ;; => GOST3412-2015

;; To generate a secret key GOST28147-89 use `generate-secret-key` function with a parameter.
;; This will return a 256-bit random secret key as a SecretKeySpec object.
;; The algorithm is set to GOST28147.
(def secret-key-89 (e/generate-secret-key e/gost28147))
(e/algo-name secret-key-89) ;; => GOST28147

;; To convert a SecretKeySpec to a byte array:
(e/secret-key->byte-array secret-key-2015) ;; => [B
;; [-38, -86, 71, -42, -69, 73, -33, 53, 72, 80, 38, 26, 57, 69, -114, -1,
;; -119, 13, 113, -84, -31, 54, -128, 114, -79, -55, 85, 126, 105, -96,
;; -37, -128]

;; To convert a byte array to SecretKeySpec:
(e/byte-array->secret-key (byte-array [-38, -86, 71, -42, -69, 73, -33, 53, 72, 80, 38, 26, 57, 69, -114, -1,
                                       -119, 13, 113, -84, -31, 54, -128, 114, -79, -55, 85, 126, 105, -96,
                                       -37, -128])) ;; => #object[javax.crypto.spec.SecretKeySpec

;; We can generate a secret key bytes from a password.
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
;; Encryption functions
;;;;;;;;;;;;;;;

(def message "This text has length = 32 bytes.")


;; To encrypt a byte array (any binary content) in a most secured way just use `protect-bytes` function.
;; The encryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; This function calculates Mac for plain data, then
;; compress a plain data to hide information structure, then
;; encrypts data and Mac in CFB mode with always random IV.
;; The encrypted bytes from the same message and same key are always different!
(def encrypted-message (e/protect-bytes secret-key-2015 (.getBytes message))) ;; Returns bytes array with structure:
;; [random(IV), encrypted(Mac), encrypted(compressed-data)]

;; To decrypt and restore a plain text just use `unprotect-bytes` function.
;; The decryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; This function decrypts Mac and data, then
;; decompress data, then calculate Mac for decompressed data, then
;; compare Mac from a message and Mac calculated.
;; If Macs are the same then return plain data, otherwise throw an Exception.
(def decrypted-message (e/unprotect-bytes secret-key-2015 encrypted-message))

(= message (String. ^bytes decrypted-message)) ;; => true

;; To encrypt a file (any binary content) in a most secured way just use `protect-file` function.
;; The encryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; This function calculates Mac for plain file, then
;; compress a plain file to hide information structure, then
;; encrypts data and Mac in CFB mode with always random IV.
;; The encrypted bytes from the same message and same key are always different!
(e/protect-file secret-key-2015 "dev/src/examples/plain32.txt" "target/plain32.enc") ;; Encrypted file has structure:
;; random(IV), encrypted(Mac), encrypted(compressed-data).

;; To decrypt a file just use `unprotect-file` function.
;; The decryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; This function decrypts Mac and data, then
;; decompress data in a file, then calculate Mac for decompressed data, then
;; compare Mac from the message and Mac calculated.
;; If Macs are the same then return output file name as String, otherwise throw an Exception.
(e/unprotect-file secret-key-2015 "target/plain32.enc" "target/plain32.txt")

(= (slurp "dev/src/examples/plain32.txt") (slurp "target/plain32.txt")) ;; => true



;;;;;;;;;;;;;;;
;; Mac functions
;;;;;;;;;;;;;;;

;; To calculate Mac for a file (any binary file) use `mac-stream` function.
;; The encryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; Mac value from the same data and same SecretKeySpec is always the same.
(e/mac-stream secret-key-2015 "dev/src/examples/plain32.txt") ;; => [B
;; [-111, 125, 10, -34, -109, -109, 41, 115, 81, 61, -90, -80, 16, 71, -108, 91]

;; To calculate Mac for a byte array (any binary file) use the same `mac-stream` function.
;; The encryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; Mac value from the same data and same SecretKeySpec is always the same.
(e/mac-stream secret-key-2015 (.getBytes message)) ;; => [B
;; [-111, 125, 10, -34, -109, -109, 41, 115, 81, 61, -90, -80, 16, 71, -108, 91]


;;;;;;;;;;;;;;;
;; Low-level functions
;;;;;;;;;;;;;;;

;; IV length depends on encryption mode and algorithm
(e/iv-length-by-algo-mode e/gost3412-2015 :cfb-mode)        ;; => 16
(e/iv-length-by-algo-mode e/gost3412-2015 :cbc-mode)        ;; => 16
(e/iv-length-by-algo-mode e/gost3412-2015 :ctr-mode)        ;; => 8 !!

(e/iv-length-by-algo-mode e/gost28147 :cfb-mode)        ;; => 8
(e/iv-length-by-algo-mode e/gost28147 :cbc-mode)        ;; => 8
(e/iv-length-by-algo-mode e/gost28147 :ctr-mode)        ;; => 8

;; Mac length
(e/mac-length-by-algo e/gost3412-2015)                      ;; => 16
(e/mac-length-by-algo e/gost28147)                          ;; => 4


