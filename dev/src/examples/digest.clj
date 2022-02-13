(ns examples.digest
  (:require
    [org.rssys.gost.common :as common]
    [org.rssys.gost.digest :as d]))


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

;; To generate GOST3411-2012-512 digest from byte array use `digest-2012-512` function
(def d5 (d/digest-2012-512 (.getBytes message)))

(common/bytes-to-hex d5)                                    ;; =>
;; "d2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b97e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe"

;; To generate GOST3411-2012-512 digest from file use the same `GOST3411-2012-512` function
(def d6 (d/digest-2012-512 "dev/src/examples/plain32.txt"))

(common/bytes-to-hex d6)                                    ;; =>
;; "7f75cf439c41420b25a3964ab0608af592c9af44e852dcbc18ae9fcfa0c2d7e3edda83715d23d30e5d3dc521290c66980695faa69adc7c5854ced01f0af6f0e9"
