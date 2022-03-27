(ns org.rssys.gost.armor-test
  (:require
    [clojure.string :as string]
    [clojure.test :refer [deftest is testing]]
    [matcho.core :refer [match]]
    [org.rssys.gost.armor :as a]
    [org.rssys.gost.pem :as p]))


(deftest sign-message-test
  (testing "Armored message produced successfully"
    (let [private-key-256  (p/pem->private-key (slurp "test/data/test-private-key-256.pem"))
          plain-32-message (slurp "test/data/plain32.txt")
          big-txt          (slurp "test/data/big.txt")
          armored-message  (a/sign-message private-key-256 plain-32-message)
          armored-big      (a/sign-message private-key-256 big-txt)
          restored-message (a/read-armored-body armored-message)
          restored-big     (a/read-armored-body armored-big)
          struct-32        (p/read-struct-from-pem armored-message)
          struct-big       (p/read-struct-from-pem armored-big)]
      (is (string/includes? armored-message plain-32-message) "Armored message contains plain message")
      (is (string/includes? armored-message "time:") "Armored message contains time of signature")
      (is (string/includes? armored-message "BEGIN SIGNATURE") "Armored message contains signature")
      (is (= restored-message plain-32-message) "Restored data from armor is the same")
      (is (= big-txt restored-big) "Restored data from armor is the same")
      (match struct-32 {:data bytes? :type "SIGNATURE" :headers {"time" string?}})
      (match struct-big {:data bytes? :type "SIGNATURE" :headers {"time" string?}})))

  (testing "Armored message with headers produced successfully"
    (let [private-key-256  (p/pem->private-key (slurp "test/data/test-private-key-256.pem"))
          plain-32-message (slurp "test/data/plain32.txt")
          armored-message  (a/sign-message private-key-256 plain-32-message
                             :headers {:issuer "Certification Authority" :address "Moscow"})]
      (is (string/includes? armored-message plain-32-message) "Armored message contains plain message")
      (is (string/includes? armored-message "issuer") "Armored message contains issuer data")
      (is (string/includes? armored-message "Certification Authority") "Armored message contains issuer data")
      (is (string/includes? armored-message "address") "Armored message contains address data")
      (is (string/includes? armored-message "Moscow") "Armored message contains address data"))))



(deftest verify-message-test

  (testing "Verification tests for armored message"
    (let [public-key-256   (p/pem->public-key (slurp "test/data/test-public-key-256.pem"))
          plain-32-message (slurp "test/data/plain32.txt")
          result-plain-32  (a/verify-message public-key-256 (slurp "test/data/armored-plain32.pem"))
          big-armored-text (slurp "test/data/big-armored.txt")
          restored-big (a/verify-message public-key-256 big-armored-text)]

      (is (= result-plain-32 plain-32-message) "Restored message is equal to original one")

      (is (thrown-with-msg? Exception #"Signature is not valid"
            (a/verify-message public-key-256 (slurp "test/data/bad-ts-armored-plain32.pem")))
        "Read armored message with modified time rises an Exception about incorrect signature")

      (is (thrown-with-msg? Exception #"Signature is not valid"
            (a/verify-message public-key-256 (slurp "test/data/bad-msg-armored-plain32.pem"))
            "Read armored message with modified message rises an Exception about incorrect signature"))

      (is (= restored-big (slurp "test/data/big.txt")) "Restored message is equal to original one")))

  (testing "Verification tests for armored message with headers"
    (let [public-key-256   (p/pem->public-key (slurp "test/data/test-public-key-256.pem"))
          plain-32-message (slurp "test/data/plain32.txt")
          result-plain-32  (a/verify-message public-key-256 (slurp "test/data/armored-plain32-with-headers.pem"))]

      (is (= result-plain-32 plain-32-message) "Restored message is equal to original one")

      (is (thrown-with-msg? Exception #"Signature is not valid"
            (a/verify-message public-key-256 (slurp "test/data/bad-issuer-armored-plain32-with-headers.pem")))
        "Read armored message with modified issuer rises an Exception about incorrect signature")

      (is (thrown-with-msg? Exception #"Signature is not valid"
            (a/verify-message public-key-256 (slurp "test/data/bad-msg-armored-plain32-with-headers.pem"))
            "Read armored message with modified message rises an Exception about incorrect signature"))

      (is (thrown-with-msg? Exception #"Signature is not valid"
            (a/verify-message public-key-256 (slurp "test/data/bad-addr-armored-plain32-with-headers.pem"))
            "Read armored message with modified address rises an Exception about incorrect signature"))

      (is (thrown-with-msg? Exception #"Signature is not valid"
            (a/verify-message public-key-256 (slurp "test/data/bad-big-armored.txt"))
            "Read armored message with modified message rises an Exception about incorrect signature"))

      (is (thrown-with-msg? Exception #"Signature is not valid"
            (a/verify-message public-key-256 (slurp "test/data/bad-ts-big-armored.txt"))
            "Read armored message with modified time rises an Exception about incorrect signature")))))
