(ns org.rssys.gost.common-test
  (:require
    [clojure.test :as test :refer [deftest is testing]]
    [matcho.core :refer [match]]
    [org.rssys.gost.common :as sut]))


(deftest ^:unit jce-unlimited?-test
  (testing "JDK has unlimited cryptography strength"
    (is (sut/jce-unlimited?))))


(deftest ^:unit bytes-to-hex-test
  (testing "Encoding / decoding hex to bytes works as expected"
    (let [test-string   "I am a test string! !@#$$%&*!*"
          test-bytes    (.getBytes test-string)
          hex-string    (sut/bytes-to-hex test-bytes)
          string-bytes  (sut/hex-to-bytes hex-string)
          result-string (String. ^bytes string-bytes)]
      (match result-string test-string))))
