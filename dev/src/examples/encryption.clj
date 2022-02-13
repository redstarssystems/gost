(ns examples.encryption
  (:require
    [org.rssys.gost.encrypt :as e]))

;; High-level functions

;; To generate a secret key for the GOST3412-2015 use `generate-secret-key` function.
;; This will return a 256-bit random secret key as a SecretKeySpec object.
;; The algorithm is set to GOST3412-2015
(def secret-key-2015 (e/generate-secret-key))
(e/algo-name secret-key-2015)                               ;; => GOST3412-2015

;; To generate a secret key GOST28147-89 use `generate-secret-key` function with a parameter.
;; This will return a 256-bit random secret key as a SecretKeySpec object.
;; The algorithm is set to GOST28147.
(def secret-key-89 (e/generate-secret-key e/gost28147))
(e/algo-name secret-key-89)                                 ;; => GOST28147

;; To convert a SecretKeySpec to a byte array:
(e/secret-key->byte-array secret-key-2015)                  ;; => [B
;; [-38, -86, 71, -42, -69, 73, -33, 53, 72, 80, 38, 26, 57, 69, -114, -1,
;; -119, 13, 113, -84, -31, 54, -128, 114, -79, -55, 85, 126, 105, -96,
;; -37, -128]

;; To convert a byte array to SecretKeySpec:
(e/byte-array->secret-key (byte-array [-38, -86, 71, -42, -69, 73, -33, 53, 72, 80, 38, 26, 57, 69, -114, -1,
                                       -119, 13, 113, -84, -31, 54, -128, 114, -79, -55, 85, 126, 105, -96,
                                       -37, -128]))         ;; => #object[javax.crypto.spec.SecretKeySpec

;; We can generate a secret key bytes from a password.
;; This function always return the same bytes value from the same String password.
;; By default, it uses min 10000 iterations of PBKDF2WITHHMACGOST3411 algorithm, recommended by NIST
(e/generate-secret-bytes-from-password "qwerty12345")       ;; => [B
;;[-113, 62, 87, -90, 116, -44, -20, -98, 4, -108, 77, -59, -22, 25, -73,
;; 20, -31, 62, -86, 19, 103, 81, -64, 32, 74, 81, -32, -97, -78, 123,
;; -82, -70]

;; To convert it to SecretKeySpec
(e/byte-array->secret-key
  (e/generate-secret-bytes-from-password "qwerty12345"))    ;; => #object[javax.crypto.spec.SecretKeySpec

;;;;;;;;;;;;;;;
;; Encryption functions. High-level functions
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

(= message (String. ^bytes decrypted-message))              ;; => true

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
;; High-level functions
;;;;;;;;;;;;;;;

;; To calculate Mac for a file (any binary file) use `mac-stream` function.
;; The encryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; Mac value from the same data and same SecretKeySpec is always the same.
(e/mac-stream secret-key-2015 "dev/src/examples/plain32.txt") ;; => [B
;; [-111, 125, 10, -34, -109, -109, 41, 115, 81, 61, -90, -80, 16, 71, -108, 91]

;; To calculate Mac for a byte array (any binary file) use the same `mac-stream` function.
;; The encryption algorithm GOST3412-2015 or GOST28147-89 is already set in SecretKeySpec.
;; Mac value from the same data and same SecretKeySpec is always the same.
(e/mac-stream secret-key-2015 (.getBytes message))          ;; => [B
;; [-111, 125, 10, -34, -109, -109, 41, 115, 81, 61, -90, -80, 16, 71, -108, 91]


;;;;;;;;;;;;;;;
;; Low-level functions.
;; Don't use these low-level functions if you are not sure.
;; Use only high-level functions
;;;;;;;;;;;;;;;

;; IV length depends on encryption mode and algorithm
(e/iv-length-by-algo-mode e/gost3412-2015 :cfb-mode)        ;; => 16
(e/iv-length-by-algo-mode e/gost3412-2015 :cbc-mode)        ;; => 16
(e/iv-length-by-algo-mode e/gost3412-2015 :ctr-mode)        ;; => 8 !!

(e/iv-length-by-algo-mode e/gost28147 :cfb-mode)            ;; => 8
(e/iv-length-by-algo-mode e/gost28147 :cbc-mode)            ;; => 8
(e/iv-length-by-algo-mode e/gost28147 :ctr-mode)            ;; => 8

;; Mac length
(e/mac-length-by-algo e/gost3412-2015)                      ;; => 16
(e/mac-length-by-algo e/gost28147)                          ;; => 4


;; Random IV generation

(e/new-iv-8)                                                ;; => [B
;; [25, 117, -36, -32, -87, -128, -25, 23]

(e/new-iv-16)                                               ;; => [B
;; [29, -49, 83, 120, -125, 95, 41, -54, -11, -37, -2, -19, 123, -122,
;; -21, 6]

;; Also we can generate IV depend on cipher mode and algorithm name
(e/new-iv e/gost28147 :cfb-mode)                            ;; => [B
;; [-101, 29, 29, 55, 112, 14, 55, 104]

(e/new-iv e/gost3412-2015 :cbc-mode)                        ;; => [B
;; [6, 87, 96, -83, -128, 25, -57, -70, -54, 51, 9, -26, 73, -103, 64, 67]

;; Warning! IV for :ctr-mode is always 8 bytes length for any algorithm
(e/new-iv e/gost3412-2015 :ctr-mode)                        ;; => [B => [45, -71, 116, -67, 9, -39, -101, -51]
(e/new-iv e/gost28147 :ctr-mode)                            ;; => [B => [8, 39, -126, -5, 122, -120, 1, -108]


;; Create Cipher for GOST28147 in CFB, CTR, CBC mode
(def cipher1 (e/init-cipher-mode e/gost28147 :cfb-mode))
(def cipher2 (e/init-cipher-mode e/gost28147 :ctr-mode))
(def cipher3 (e/init-cipher-mode e/gost28147 :cbc-mode))


;; Create Cipher for GOST3412-2015 in CFB, CTR, CBC mode
(def cipher4 (e/init-cipher-mode e/gost3412-2015 :cfb-mode))
(def cipher5 (e/init-cipher-mode e/gost3412-2015 :ctr-mode))
(def cipher6 (e/init-cipher-mode e/gost3412-2015 :cbc-mode))


;; Init GOST 28147 with named parameters
(def secret-key (e/generate-secret-key e/gost28147))        ;; generate secret key
(def iv (e/new-iv (e/algo-name secret-key) :cfb-mode))      ;; generate new random IV
(def algo-param-spec (e/init-gost-named-params (e/algo-name secret-key) iv "E-A")) ;; Init GOST with "E-A" parameters

;; Init GOST 28147 with OID parameters
;; See https://cpdn.cryptopro.ru/content/csp40/html/group___pro_c_s_p_ex_CP_PARAM_OIDS.html
(e/init-gost-oid-params e/gost28147 iv (org.bouncycastle.asn1.ASN1ObjectIdentifier. "1.2.643.2.2.31.1"))


;; Init GOST 28147 with S-box as binary array
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


(e/init-gost-sbox-binary-params e/gost28147 iv (byte-array s-box-crypto-pro-a))


;; Init cipher for GOST3412-2015,  generate random IV automatically
(def secret-key-2015 (e/generate-secret-key e/gost3412-2015))
(def cipher-2015 (e/new-encryption-cipher secret-key :cfb-mode))
;; extract IV
(.getIV cipher-2015)                                             ;; => [B
;;[105, 13, 115, 71, 2, -23, 6, 82, -30, -13, 113, -12, -34, 69, -6, 27]

;; Init cipher for GOST28147,  generate random IV automatically
(def secret-key-89 (e/generate-secret-key e/gost28147))
(def cipher-89 (e/new-encryption-cipher secret-key-89 :cfb-mode))
;; extract IV
(.getIV cipher-89) ;; => [-84, -116, -60, -99, 89, 43, -107, 127]
