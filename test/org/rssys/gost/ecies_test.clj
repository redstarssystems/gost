(ns org.rssys.gost.ecies-test
  (:require
    [clojure.java.io :as io]
    [clojure.test :as test :refer [deftest is testing]]
    [matcho.core :refer [match]]
    [org.rssys.gost.ecies :as sut]
    [org.rssys.gost.sign :as s])
  (:import
    (java.io
      File)))


;; Generate Alice keypair 256-bit length
(def alice-kp (s/gen-keypair-256))

(def alice-private-key (s/get-private alice-kp))
(def alice-public-key (s/get-public alice-kp))


;; Generate Bob keypair 256-bit length
(def bob-kp (s/gen-keypair-256))

(def bob-private-key (s/get-private bob-kp))
(def bob-public-key (s/get-public bob-kp))


(def message "This is message.")

(def big-text (slurp "test/data/big.txt"))


;; Generate Alice's keypair 512-bit length
(def alice-kp-512 (s/gen-keypair-512))

(def alice-private-key-512 (s/get-private alice-kp-512))
(def alice-public-key-512 (s/get-public alice-kp-512))


;; Generate Bob's keypair 512-bit length
(def bob-kp-512 (s/gen-keypair-512))

(def bob-private-key-512 (s/get-private bob-kp-512))
(def bob-public-key-512 (s/get-public bob-kp-512))


(deftest encrypt-bytes-test
  (let [encrypted-data-256 (sut/encrypt-bytes alice-private-key bob-public-key (.getBytes message))
        encrypted-data-512 (sut/encrypt-bytes alice-private-key-512 bob-public-key-512 (.getBytes message))]
    (is (> (alength encrypted-data-256) 117) "Encrypted data has length more than encrypted random-iv")
    (is (> (alength encrypted-data-512) 181) "Encrypted data has length more than encrypted random-iv")))



(deftest decrypt-bytes-test
  (testing "Data is decrypted successfully"
    (let [encrypted-data-256 (sut/encrypt-bytes alice-private-key bob-public-key (.getBytes big-text))
          encrypted-data-512 (sut/encrypt-bytes alice-private-key-512 bob-public-key-512 (.getBytes big-text))
          result-256         (String. (sut/decrypt-bytes bob-private-key alice-public-key encrypted-data-256))
          result-512         (String. (sut/decrypt-bytes bob-private-key-512 alice-public-key-512 encrypted-data-512))]
      (match result-256 big-text)
      (match result-512 big-text)))

  (testing "Corrupted encrypted random-iv cannot be decrypted"
    (let [encrypted-data           (sut/encrypt-bytes alice-private-key bob-public-key (.getBytes big-text))
          corrupted-encrypted-data (byte-array (update (into [] encrypted-data) 20 inc))]
      (is (thrown-with-msg? Exception #"unable to process block"
            (sut/decrypt-bytes bob-private-key alice-public-key corrupted-encrypted-data)))))

  (testing "Wrong header is detected "
    (is (thrown-with-msg? Exception #"Wrong encrypted header length"
          (sut/decrypt-bytes bob-private-key alice-public-key (byte-array [2 0 1]))))))


(deftest encrypt-file-test

  (testing "Encrypt/decrypt-file success for a big file"
    (let [input-filename          "test/data/big.txt"

          output-file-egz-256     (File/createTempFile "filename" ".egz")
          output-file-egz-512     (File/createTempFile "filename" ".egz")
          _                       (.deleteOnExit output-file-egz-256)
          _                       (.deleteOnExit output-file-egz-512)

          output-filename-egz-256 (.getAbsolutePath output-file-egz-256)
          output-filename-egz-512 (.getAbsolutePath output-file-egz-512)

          er1                     (sut/encrypt-file alice-private-key bob-public-key input-filename output-filename-egz-256)
          er2                     (sut/encrypt-file alice-private-key-512 bob-public-key-512 input-filename output-filename-egz-512)

          output-file-txt-256     (File/createTempFile "filename" ".txt")
          output-file-txt-512     (File/createTempFile "filename" ".txt")
          _                       (.deleteOnExit output-file-txt-256)
          _                       (.deleteOnExit output-file-txt-512)

          output-filename-txt-256 (.getAbsolutePath output-file-txt-256)
          output-filename-txt-512 (.getAbsolutePath output-file-txt-512)

          dr1                     (sut/decrypt-file bob-private-key alice-public-key output-filename-egz-256 output-filename-txt-256)
          dr2                     (sut/decrypt-file bob-private-key-512 alice-public-key-512 output-filename-egz-512 output-filename-txt-512)
          input-content           (slurp input-filename)]

      (is (= output-filename-egz-256 er1))
      (is (= output-filename-egz-512 er2))

      (is (= output-filename-txt-256 dr1))
      (is (= output-filename-txt-512 dr2))

      (match input-content (slurp output-file-txt-256))
      (match input-content (slurp output-file-txt-512))

      (.delete (io/file output-filename-egz-256))
      (.delete (io/file output-filename-egz-512))
      (.delete (io/file output-filename-txt-256))
      (.delete (io/file output-filename-txt-512)))))



