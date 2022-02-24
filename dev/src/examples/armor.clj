(ns examples.armor
  "Examples for armored functions"
  (:require
    [org.rssys.gost.armor :as a]
    [org.rssys.gost.pem :as p]
    [org.rssys.gost.sign :as s])
  (:import
    (java.time.format
      DateTimeFormatter
      FormatStyle)))


;; Read test public and private keys
(def public-key-256 (p/pem->public-key (slurp "test/data/test-public-key-256.pem")))
(def private-key-256 (p/pem->private-key (slurp "test/data/test-private-key-256.pem")))


;; Read plain text
(def plain-32-message (slurp "test/data/plain32.txt"))


;; Sign message + time and produce armored message: plain text + time + signature
(def armored-message (a/sign-message private-key-256 plain-32-message))


;; Verify signature for message + time and if signature is valid return message
(def restored-message (a/verify-message public-key-256 armored-message))


;; Verify signature from armored file
(def restored-message-from-file (a/verify-message public-key-256 (slurp "test/data/armored-plain32.pem")))


;; Read armored message with modified time rises an Exception about incorrect signature
(a/verify-message public-key-256 (slurp "test/data/bad-ts-armored-plain32.pem"))


;; Read armored message with modified message rises an Exception about incorrect signature
(a/verify-message public-key-256 (slurp "test/data/bad-msg-armored-plain32.pem"))


;; Sign message with headers data
(def armored-message-with-headers
  (a/sign-message private-key-256 plain-32-message
    :headers {:issuer "Certification Authority" :address "Moscow"}))


;; Sign message with headers data and custom date-time formatter
(def armored-message-with-headers-custom-formatter
  (a/sign-message private-key-256 plain-32-message
    :headers {:issuer "Certification Authority" :address "Moscow"}
    :datetime-formatter (DateTimeFormatter/ofLocalizedDateTime FormatStyle/LONG)))


;; Verify message with headers
(a/verify-message public-key-256 (slurp "test/data/armored-plain32-with-headers.pem"))


;; Read different types of tampered data and rises an Exception about incorrect signature
(a/verify-message public-key-256 (slurp "test/data/bad-msg-armored-plain32-with-headers.pem"))
(a/verify-message public-key-256 (slurp "test/data/bad-issuer-armored-plain32-with-headers.pem"))
(a/verify-message public-key-256 (slurp "test/data/bad-addr-armored-plain32-with-headers.pem"))


;; read big armored text
(def big-armored-text (slurp "test/data/big-armored.txt"))


;; verify signature for big text
(def restored-big (a/verify-message public-key-256 big-armored-text))


;; check that texts are equal
(= restored-big (slurp "test/data/big.txt"))


;; Read different types of tampered data and got Exception about incorrect signature
(a/verify-message public-key-256 (slurp "test/data/bad-big-armored.txt"))
(a/verify-message public-key-256 (slurp "test/data/bad-ts-big-armored.txt"))

