(ns org.rssys.gost.common-test
  (:require
    [clojure.test :as test :refer [deftest is testing]]
    [matcho.core :refer [match]]
    [org.rssys.gost.common :as sut]))


(deftest jce-unlimited?-test
  (testing "JDK has unlimited cryptography strength"
    (is (sut/jce-unlimited?))))


(deftest bytes-to-hex-test
  (testing "Encoding / decoding hex to bytes works as expected"
    (let [test-string   "I am a test string! !@#$$%&*!*"
          test-bytes    (.getBytes test-string)
          hex-string    (sut/bytes-to-hex test-bytes)
          string-bytes  (sut/hex-to-bytes hex-string)
          result-string (String. ^bytes string-bytes)]
      (match result-string test-string))))


(deftest base64-encode-test
  (let [s "Hello"
        result (sut/base64-encode (.getBytes s))]
    (match result "SGVsbG8=")))


(deftest base64-decode-test
  (let [base64-s "SGVsbG8="
        result (sut/base64-decode base64-s)]
    (match (String. result) "Hello")))
