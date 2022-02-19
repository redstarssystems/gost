(ns examples.digest
  (:require
    [org.rssys.gost.common :as common]
    [org.rssys.gost.digest :as d]
    [org.rssys.gost.encrypt :as e]))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High-level functions

(def message "The quick brown fox jumps over the lazy dog")


;; To generate GOST3411-94 digest from byte array use `digest-3411-94` function
(def d1 (d/digest-3411-94 (.getBytes message)))

(common/bytes-to-hex d1)                                    ;; =>
;; "9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76"

;; To generate GOST3411-94 digest from file use the same `digest-3411-94` function
(def d2 (d/digest-3411-94 "dev/src/examples/plain32.txt"))

(common/bytes-to-hex d2)                                    ;; =>
;; "94ca6fc62ae26d3bb0109c16e6a5749c291bbdd0cdf5231e3f4073679227b9fb"

;; To generate GOST3411-2012-256 digest from byte array use `digest-2012-256` function
(def d3 (d/digest-2012-256 (.getBytes message)))

(common/bytes-to-hex d3)                                    ;; =>
;; "3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4"

;; To generate GOST3411-2012-256 digest from file use the same `GOST3411-2012-256` function
(def d4 (d/digest-2012-256 "dev/src/examples/plain32.txt"))

(common/bytes-to-hex d4)                                    ;; =>
;; "ee363d5e40c1ff1965ee308beef1ca153c1d56d377a63be29924731732f2c697"

(common/bytes-to-hex (d/digest-2012-256 "test/data/big.txt")) ;;=> "a22189fd09dea6c60138b821dd48c42a9b33910faf70413dc76f374a29574b19"
;; openssl dgst -streebog256 test/data/big.txt
;;streebog256(test/data/big.txt)= a22189fd09dea6c60138b821dd48c42a9b33910faf70413dc76f374a29574b19

;; To generate GOST3411-2012-512 digest from byte array use `digest-2012-512` function
(def d5 (d/digest-2012-512 (.getBytes message)))

(common/bytes-to-hex d5)                                    ;; =>
;; "d2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b97e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe"

;; To generate GOST3411-2012-512 digest from file use the same `GOST3411-2012-512` function
(def d6 (d/digest-2012-512 "dev/src/examples/plain32.txt"))

(common/bytes-to-hex d6)                                    ;; =>
;; "7f75cf439c41420b25a3964ab0608af592c9af44e852dcbc18ae9fcfa0c2d7e3edda83715d23d30e5d3dc521290c66980695faa69adc7c5854ced01f0af6f0e9"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; generate secret key bytes from password
(def secret-key (e/generate-secret-bytes-from-password "12345678"))


;; Generate HMAC using GOST3411-94 and secret-key bytes
(def h1 (d/hmac-3411-94 (.getBytes message) secret-key))

(common/bytes-to-hex h1)                                    ;; =>
;; "1ffb045ab775c674b5809d6f5c180c73be459223e93951e8c19cc1e0ed559b20"

;; Generate HMAC using GOST3411-2012-256 and secret-key bytes
(def h2 (d/hmac-2012-256 (.getBytes message) secret-key))

(common/bytes-to-hex h2)                                    ;; =>
;; "405854baba2cc90661f1ff08e40c2cd0fb36869a5a32f655f51ea6fd577c6d84"

;; Generate HMAC using GOST3411-2012-512 and secret-key bytes
(def h3 (d/hmac-2012-512 (.getBytes message) secret-key))

(common/bytes-to-hex h3)                                    ;; =>
;; "14923d761858aa272028855999c0bd3f37964e98bb3bb163825ecfbcd049e10f612566053031bec01611bc9584ef24aa80073cecc51d125fe989a973dd1f6813"


;; To generate GOST3411-2012-256 HMAC from file use the same `hmac-2012-256` function
(def h4 (d/hmac-2012-256 "dev/src/examples/plain32.txt" secret-key))

(common/bytes-to-hex h4)                                    ;; =>
;; "2c36afad546eb7026b1bfd92dc83a6e6cfd20f301a786fed41fd3c2213214d43"
