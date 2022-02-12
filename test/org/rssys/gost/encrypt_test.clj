(ns org.rssys.gost.encrypt-test
  (:require
    [clojure.java.io :as io]
    [clojure.string :as string]
    [clojure.test :as test :refer [deftest is testing]]
    [matcho.core :refer [match]]
    [org.rssys.gost.common :as common]
    [org.rssys.gost.encrypt :as sut])
  (:import
    (clojure.lang
      ExceptionInfo)
    (java.io
      ByteArrayOutputStream
      File)
    (java.security.spec
      AlgorithmParameterSpec)
    (javax.crypto
      Cipher)
    (javax.crypto.spec
      IvParameterSpec
      SecretKeySpec)
    (org.bouncycastle.asn1
      ASN1ObjectIdentifier)))


(def test-secret-key (byte-array [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31]))
(def test-iv-8 (byte-array [0 1 2 3 4 5 6 7]))
(def test-iv-16 (byte-array [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15]))


(def ^:const plain-32 "This is message, length=32 bytes")
(def plain-32-hex (common/bytes-to-hex (.getBytes plain-32)))

(def ^:const plain-50 "Suppose the original message has length = 50 bytes")
(def plain-50-hex (common/bytes-to-hex (.getBytes plain-50)))

(def test-gost28147-encrypted-bytes32-cfb "9e48e38e51824af47bf53372770547ae5a089435d9a9faa89a51cc73d4050634")
(def test-gost28147-encrypted-bytes50-cfb "9955fa8d1e985cf4a0126e2f974543741107259d25eedb4422ba8aa95903ddafd0935cd9a0dff22b171c90dad6ee4796ab95")
(def test-gost28147-encrypted-bytes32-ctr "9e48e38e51824af4e0e521ba4307bea9b985eb7c9fd11c5ac6e6848b991dc8aa")
(def test-gost28147-encrypted-bytes50-ctr "9955fa8d1e985cf4f9e837e94d12b2e2f087ef7ed8c8111486b5c38cc001ccaa760f885eb6f1a9e082bb24294ef2ca00be19")
(def test-gost28147-encrypted-bytes32-cbc "8a5b51c05812e8a613445f3002f1b2c7b3acfb3949e3c4cf73d6705dead78bd17bc122e390e81832")
(def test-gost28147-encrypted-bytes50-cbc "c908bca2ff21bce855fc19bcca0af589647134640424511e4f205591033856e1734681cf9e6d38513be274fcf90630aae0c0efcffdaf2b50")

(def test-gost3412-2015-encrypted-bytes32-cfb "9ed1514411164c6b5aac6bc8fa9fdea6202e83d3253e76cc007d323ffee70d9d")
(def test-gost3412-2015-encrypted-bytes50-cfb "99cc48475e0c5a6b43a17d9bf48ad2ed93f1f5595cd41e11937697759acd7a733b6050dd6bde06b6ef00ee422ded0e0339e3")
(def test-gost3412-2015-encrypted-bytes32-ctr "8795d63bd3b60c2dae98a7b8c4ca468e6e364a7c1778a1b928ec6bb0fcf88f43")
(def test-gost3412-2015-encrypted-bytes50-ctr "8088cf389cac1a2db795b1ebcadf4ac527344e7e5061acf768bf2cb7a5e48b436fe37248fa52f5edd355284d642d7efab087")
(def test-gost3412-2015-encrypted-bytes32-cbc "fd459507ac1ebb8c48c3c3157700bdc4f292fa301ad81c82674044de0a9e34b4647fa222f37a7e86d3bf9992d049f3a2")
(def test-gost3412-2015-encrypted-bytes50-cbc "a3a98ce9352b3c72373c4594c8213f2d5619a35d92d62fabbe3901cf4177ca91ffecd9913a2f7a8d13880319cb091258b04da4e6366df0a3b28ee8d1cd60bfb5")

(def test-key-gost-3412 "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
(def test-text-gost3412 "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011")
(def test-mac-gost28147-plain-32 "bde344b8")
(def test-mac-gost28147-plain-50 "fdfe1840")
(def test-mac-gost3412-2015-plain-32 "a1395ed7395488df5672e8b83b3ddac5")
(def test-mac-gost3412-2015-plain-50 "b50e2700a3fbd23fc19de19a1e56de10")

(def test-mac-gost3412-2015-big-txt "1a2e5976eeb3842a146eb2eb1a3631ec")
(def test-mac-gost28147-big-txt "f470cdee")


(deftest ^:unit generate-secret-key-test

  (testing "Generate secret key for GOST3412-2015"
    (let [secret-key (sut/generate-secret-key)]
      (is (instance? SecretKeySpec secret-key))
      (match (sut/algo-name secret-key) sut/gost3412-2015)))

  (testing "Generate secret key for GOST28147"
    (let [secret-key (sut/generate-secret-key "GOST28147")]
      (is (instance? SecretKeySpec secret-key))
      (match (sut/algo-name secret-key) sut/gost28147)))

  (testing "Wrong algorithm names are not supported"
    (is (thrown-with-msg? ExceptionInfo #"Allowed values for algorithm"
          (sut/generate-secret-key "wrong-algo-name")))))


(deftest ^:unit secret-key->byte-array-test
  (testing "Converting SecretKey to plain bytes array is successful"
    (let [secret-key (sut/generate-secret-key)
          result     (sut/secret-key->byte-array secret-key)]
      (match (alength result) sut/secret-key-length-bytes)
      (is (bytes? result)))))


(deftest ^:unit byte-array->secret-key-test

  (testing "Converting plain bytes array to SecretKey for GOST3412-2015 is successful"
    (let [secret-bytes (byte-array (range sut/secret-key-length-bytes))
          secret-key   (sut/byte-array->secret-key secret-bytes)]
      (is (instance? SecretKeySpec secret-key))
      (match (sut/algo-name secret-key) sut/gost3412-2015)))

  (testing "Converting bytes array to SecretKey for GOST28147 is successful "
    (let [secret-bytes (byte-array (range sut/secret-key-length-bytes))
          secret-key   (sut/byte-array->secret-key secret-bytes "GOST28147")]
      (alength secret-bytes)
      (is (instance? SecretKeySpec secret-key))
      (match (sut/algo-name secret-key) sut/gost28147)))

  (testing "Converting bytes array with weak key in buffer is not allowed"
    (let [secret-bytes (byte-array (into [] (repeat 32 1)))]
      (is (thrown-with-msg? ExceptionInfo #"Byte array contains a weak key"
            (sut/byte-array->secret-key secret-bytes sut/gost3412-2015)))))

  (testing "Converting bytes array with reduced length is not allowed"
    (let [secret-bytes (byte-array (range 31))]
      (is (thrown-with-msg? ExceptionInfo #"Byte array length should be"
            (sut/byte-array->secret-key secret-bytes "GOST3412-2015"))))))


(deftest ^:unit generate-secret-bytes-from-password-test

  (testing "Generating secret key bytes from good password is successful"
    (let [good-password "qMkaS3^%&%@lOIOJN7h7sbrgojv"
          result        (sut/generate-secret-bytes-from-password good-password 100)]
      (is (bytes? result))
      (match (alength result) sut/secret-key-length-bytes)))

  (testing "Secret keys bytes from the same password are equal"
    (let [good-password "qMkaS3^%&%@lOIOJN7h7sqbrgojv"
          secret-bytes1 (sut/generate-secret-bytes-from-password good-password 100)
          secret-bytes2 (sut/generate-secret-bytes-from-password good-password 100)]
      (match (into [] secret-bytes1) (into [] secret-bytes2))))

  (testing "Secret keys bytes from different passwords are NOT equal"
    (let [password1     "1234567890"
          password2     "123456789"
          secret-bytes1 (sut/generate-secret-bytes-from-password password1 100)
          secret-bytes2 (sut/generate-secret-bytes-from-password password2 100)]
      (is (not= (into [] secret-bytes1) (into [] secret-bytes2)))))

  (testing "Secret keys bytes has a good random quality"
    (let [password1     "1234567890"
          password2     "123456789"
          secret-bytes1 (sut/generate-secret-bytes-from-password password1 100)
          secret-bytes2 (sut/generate-secret-bytes-from-password password2 100)]
      (is (> (sut/count-unique secret-bytes1) 25))
      (is (> (sut/count-unique secret-bytes2) 25))))

  (testing "Secret keys bytes from the same password and different iteration count are NOT equal"
    (let [password1     "1234567890"
          secret-bytes1 (sut/generate-secret-bytes-from-password password1 100)
          secret-bytes2 (sut/generate-secret-bytes-from-password password1 101)]
      (is (not= (into [] secret-bytes1) (into [] secret-bytes2)))))

  (testing "Generation of secret key bytes from the weak password is not allowed"
    (let [weak-password "112233"]
      (is (thrown-with-msg? ExceptionInfo #"Byte array contains a weak password"
            (sut/generate-secret-bytes-from-password weak-password 100))))))


(deftest ^:unit init-cipher-mode-test
  (testing "Cipher for given mode is created successfully"
    (let [cipher1 (sut/init-cipher-mode sut/gost28147 :cfb-mode)
          cipher2 (sut/init-cipher-mode sut/gost28147 :ctr-mode)
          cipher3 (sut/init-cipher-mode sut/gost28147 :cbc-mode)

          cipher4 (sut/init-cipher-mode sut/gost3412-2015 :cfb-mode)
          cipher5 (sut/init-cipher-mode sut/gost3412-2015 :ctr-mode)
          cipher6 (sut/init-cipher-mode sut/gost3412-2015 :cbc-mode)]

      (is (every? #(instance? Cipher %) [cipher1 cipher2 cipher3 cipher4 cipher5 cipher6]))
      (is (every? #(string/starts-with? (sut/algo-name %) sut/gost28147) [cipher1 cipher2 cipher3]))
      (is (every? #(string/starts-with? (sut/algo-name %) sut/gost3412-2015) [cipher4 cipher5 cipher6]))

      (is (every? #(string/includes? (sut/algo-name %) "CFB") [cipher1 cipher4]))
      (is (every? #(string/includes? (sut/algo-name %) "CTR") [cipher2 cipher5]))
      (is (every? #(string/includes? (sut/algo-name %) "CBC") [cipher3 cipher6])))))


(deftest ^:unit new-iv-gost28147-test
  (testing "Generation of init vector for GOST28147-89 is successful"
    (let [iv (sut/new-iv-8)]
      (is (bytes? iv))
      (match (alength iv) sut/iv-length-8)
      (is (> (sut/count-unique iv) 4)))))


(deftest ^:unit new-iv-gost3412-2015-test
  (testing "Generation of init vector for GOST3412-2015 is successful"
    (let [iv (sut/new-iv-16)]
      (is (bytes? iv))
      (match (alength iv) sut/iv-length-16)
      (is (> (sut/count-unique iv) 8)))))


(deftest ^:unit new-iv-test
  (testing "Init vector is generated with appropriate length for algorithm"
    (let [iv1 (sut/new-iv sut/gost28147 :cfb-mode)
          iv2 (sut/new-iv sut/gost3412-2015 :cfb-mode)

          iv3 (sut/new-iv sut/gost28147 :ctr-mode)
          iv4 (sut/new-iv sut/gost3412-2015 :ctr-mode)

          iv5 (sut/new-iv sut/gost28147 :cbc-mode)
          iv6 (sut/new-iv sut/gost3412-2015 :cbc-mode)]
      (match (alength iv1) sut/iv-length-8)
      (match (alength iv2) sut/iv-length-16)

      (match (alength iv3) sut/iv-length-8)
      (match (alength iv4) sut/iv-length-8)                 ;; CTR mode for GOST3412-2015 requires IV 8 bytes

      (match (alength iv5) sut/iv-length-8)
      (match (alength iv6) sut/iv-length-16))))


(deftest ^:unit new-encryption-cipher-test

  (testing "Encryption cipher in CFB mode and init vector for GOST3412-2015 is created successfully"
    (let [secret-key (sut/generate-secret-key sut/gost3412-2015)
          cipher     (sut/new-encryption-cipher secret-key :cfb-mode)]
      (is (instance? Cipher cipher))
      (is (bytes? (.getIV cipher)))
      (is (string/includes? (sut/algo-name cipher) "CFB"))))

  (testing "Encryption cipher in CTR mode for GOST3412-2015 is created successfully"
    (let [secret-key (sut/generate-secret-key sut/gost3412-2015)
          iv         (sut/new-iv (sut/algo-name secret-key) :ctr-mode)
          cipher     (sut/new-encryption-cipher secret-key :ctr-mode (IvParameterSpec. iv))]
      (is (instance? Cipher cipher))
      (is (string/includes? (sut/algo-name cipher) "CTR"))))

  (testing "Encryption cipher in CBC mode for GOST3412-2015 is created successfully"
    (let [secret-key (sut/generate-secret-key sut/gost3412-2015)
          iv         (sut/new-iv (sut/algo-name secret-key) :cbc-mode)
          cipher     (sut/new-encryption-cipher secret-key :cbc-mode (IvParameterSpec. iv))]
      (is (instance? Cipher cipher))
      (is (string/includes? (sut/algo-name cipher) "CBC"))))

  (testing "Encryption cipher in CFB mode and init vector for GOST28147-89 is created successfully"
    (let [secret-key (sut/generate-secret-key sut/gost28147)
          cipher     (sut/new-encryption-cipher secret-key :cfb-mode)]
      (is (instance? Cipher cipher))
      (is (bytes? (.getIV cipher)))
      (is (string/includes? (sut/algo-name cipher) "CFB"))))

  (testing "Encryption cipher in CTR mode for GOST28147-89 is created successfully"
    (let [secret-key (sut/generate-secret-key sut/gost28147)
          iv         (sut/new-iv (sut/algo-name secret-key) :ctr-mode)
          cipher     (sut/new-encryption-cipher secret-key :ctr-mode (sut/init-gost-named-params (sut/algo-name secret-key) iv "E-A"))]
      (is (instance? Cipher cipher))
      (is (string/includes? (sut/algo-name cipher) "CTR"))))

  (testing "Encryption cipher in CBC mode for GOST28147-89 is created successfully"
    (let [secret-key (sut/generate-secret-key sut/gost28147)
          iv         (sut/new-iv (sut/algo-name secret-key) :cbc-mode)
          cipher     (sut/new-encryption-cipher secret-key :cbc-mode (sut/init-gost-named-params (sut/algo-name secret-key) iv "E-A"))]
      (is (instance? Cipher cipher))
      (is (string/includes? (sut/algo-name cipher) "CBC")))))


(deftest ^:unit new-decryption-cipher-test
  (testing "Decryption cipher in CFB mode and init vector for GOST3412-2015 is created successfully"
    (let [secret-key (sut/generate-secret-key sut/gost3412-2015)
          iv         test-iv-16
          cipher     (sut/new-decryption-cipher secret-key :cfb-mode (IvParameterSpec. iv))]
      (is (instance? Cipher cipher))
      (is (bytes? (.getIV cipher)))
      (is (string/includes? (sut/algo-name cipher) "CFB"))))

  (testing "Decryption cipher in CTR mode for GOST3412-2015 is created successfully"
    (let [secret-key (sut/generate-secret-key sut/gost3412-2015)
          iv         (sut/new-iv (sut/algo-name secret-key) :ctr-mode)
          cipher     (sut/new-decryption-cipher secret-key :ctr-mode (IvParameterSpec. iv))]
      (is (instance? Cipher cipher))
      (is (string/includes? (sut/algo-name cipher) "CTR"))))

  (testing "Decryption cipher in CBC mode for GOST3412-2015 is created successfully"
    (let [secret-key (sut/generate-secret-key sut/gost3412-2015)
          iv         (sut/new-iv (sut/algo-name secret-key) :cbc-mode)
          cipher     (sut/new-decryption-cipher secret-key :cbc-mode (IvParameterSpec. iv))]
      (is (instance? Cipher cipher))
      (is (string/includes? (sut/algo-name cipher) "CBC"))))

  (testing "Decryption cipher in CFB mode and init vector for GOST28147-89 is created successfully"
    (let [secret-key (sut/generate-secret-key sut/gost28147)
          iv         (sut/new-iv (sut/algo-name secret-key) :cfb-mode)
          cipher     (sut/new-decryption-cipher secret-key :cfb-mode (sut/init-gost-named-params (sut/algo-name secret-key) iv "E-A"))]
      (is (instance? Cipher cipher))
      (is (bytes? (.getIV cipher)))
      (is (string/includes? (sut/algo-name cipher) "CFB"))))

  (testing "Decryption cipher in CTR mode for GOST28147-89 is created successfully"
    (let [secret-key (sut/generate-secret-key sut/gost28147)
          iv         (sut/new-iv (sut/algo-name secret-key) :ctr-mode)
          cipher     (sut/new-decryption-cipher secret-key :ctr-mode (sut/init-gost-named-params (sut/algo-name secret-key) iv "E-A"))]
      (is (instance? Cipher cipher))
      (is (string/includes? (sut/algo-name cipher) "CTR"))))

  (testing "Decryption cipher in CBC mode for GOST28147-89 is created successfully"
    (let [secret-key (sut/generate-secret-key sut/gost28147)
          iv         (sut/new-iv (sut/algo-name secret-key) :cbc-mode)
          cipher     (sut/new-decryption-cipher secret-key :cbc-mode (sut/init-gost-named-params (sut/algo-name secret-key) iv "E-A"))]
      (is (instance? Cipher cipher))
      (is (string/includes? (sut/algo-name cipher) "CBC")))))


(deftest ^:unit init-gost-named-params-test
  (testing "Init algorithm using given init vector and S-Box named parameters is successful"
    (let [iv          (sut/new-iv sut/gost28147 :cfb-mode)
          algo-params (sut/init-gost-named-params sut/gost28147 iv "E-A")]
      (is (instance? AlgorithmParameterSpec algo-params))
      (match (into [] (.getSBox algo-params)) sut/s-box-crypto-pro-a)
      (match (into [] (.getIV algo-params)) (into [] iv)))))


(deftest ^:unit init-gost-oid-params-test
  (testing "Init algorithm using given init vector and S-Box OID parameters is successful"
    (let [iv          (sut/new-iv sut/gost28147 :cfb-mode)
          algo-params (sut/init-gost-oid-params sut/gost28147 iv (ASN1ObjectIdentifier. "1.2.643.2.2.31.1"))]
      (is (instance? AlgorithmParameterSpec algo-params))
      (match (into [] (.getSBox algo-params)) sut/s-box-crypto-pro-a)
      (match (into [] (.getIV algo-params)) (into [] iv)))))


(deftest ^:unit init-gost-sbox-binary-params-test
  (testing "Init algorithm using given init vector and S-Box binary array parameters is successful"
    (let [iv          (sut/new-iv sut/gost28147 :cfb-mode)
          algo-params (sut/init-gost-sbox-binary-params sut/gost28147 iv (byte-array sut/s-box-crypto-pro-a))]
      (is (instance? AlgorithmParameterSpec algo-params))
      (match (into [] (.getSBox algo-params)) sut/s-box-crypto-pro-a)
      (match (into [] (.getIV algo-params)) (into [] iv)))))


(deftest ^:unit encrypt-bytes-test

  (testing "GOST 28147-89 encryption in CFB mode is successful"
    (let [secret-key        (sut/byte-array->secret-key test-secret-key sut/gost28147)
          iv                test-iv-8
          algo-params       (sut/init-gost-named-params sut/gost28147 iv "E-A")
          cipher            (sut/new-encryption-cipher secret-key :cfb-mode algo-params)
          encrypted-bytes32 (sut/encrypt-bytes cipher (common/hex-to-bytes plain-32-hex))
          encrypted-bytes50 (sut/encrypt-bytes cipher (common/hex-to-bytes plain-50-hex))]
      (match (common/bytes-to-hex encrypted-bytes32) test-gost28147-encrypted-bytes32-cfb)
      (match (common/bytes-to-hex encrypted-bytes50) test-gost28147-encrypted-bytes50-cfb)))

  (testing "GOST 28147-89 encryption in CTR mode is successful"
    (let [secret-key        (sut/byte-array->secret-key test-secret-key sut/gost28147)
          iv                test-iv-8
          algo-params       (sut/init-gost-named-params sut/gost28147 iv "E-A")
          cipher            (sut/new-encryption-cipher secret-key :ctr-mode algo-params)
          encrypted-bytes32 (sut/encrypt-bytes cipher (common/hex-to-bytes plain-32-hex))
          encrypted-bytes50 (sut/encrypt-bytes cipher (common/hex-to-bytes plain-50-hex))]
      (match (common/bytes-to-hex encrypted-bytes32) test-gost28147-encrypted-bytes32-ctr)
      (match (common/bytes-to-hex encrypted-bytes50) test-gost28147-encrypted-bytes50-ctr)))

  (testing "GOST 28147-89 encryption in CBC mode is successful"
    (let [secret-key        (sut/byte-array->secret-key test-secret-key sut/gost28147)
          iv                test-iv-8
          algo-params       (sut/init-gost-named-params sut/gost28147 iv "E-A")
          cipher            (sut/new-encryption-cipher secret-key :cbc-mode algo-params)
          encrypted-bytes32 (sut/encrypt-bytes cipher (common/hex-to-bytes plain-32-hex))
          encrypted-bytes50 (sut/encrypt-bytes cipher (common/hex-to-bytes plain-50-hex))]
      (match (common/bytes-to-hex encrypted-bytes32) test-gost28147-encrypted-bytes32-cbc)
      (match (common/bytes-to-hex encrypted-bytes50) test-gost28147-encrypted-bytes50-cbc)))

  (testing "GOST 3412-2015 encryption in CFB mode is successful"
    (let [secret-key        (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          algo-params       (IvParameterSpec. test-iv-16)
          cipher            (sut/new-encryption-cipher secret-key :cfb-mode algo-params)
          encrypted-bytes32 (sut/encrypt-bytes cipher (common/hex-to-bytes plain-32-hex))
          encrypted-bytes50 (sut/encrypt-bytes cipher (common/hex-to-bytes plain-50-hex))]
      (match (common/bytes-to-hex encrypted-bytes32) test-gost3412-2015-encrypted-bytes32-cfb)
      (match (common/bytes-to-hex encrypted-bytes50) test-gost3412-2015-encrypted-bytes50-cfb)))

  (testing "GOST 3412-2015 encryption in CTR mode is successful"
    (let [secret-key        (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          algo-params       (IvParameterSpec. test-iv-8)
          cipher            (sut/new-encryption-cipher secret-key :ctr-mode algo-params)
          encrypted-bytes32 (sut/encrypt-bytes cipher (common/hex-to-bytes plain-32-hex))
          encrypted-bytes50 (sut/encrypt-bytes cipher (common/hex-to-bytes plain-50-hex))]
      (match (common/bytes-to-hex encrypted-bytes32) test-gost3412-2015-encrypted-bytes32-ctr)
      (match (common/bytes-to-hex encrypted-bytes50) test-gost3412-2015-encrypted-bytes50-ctr)))

  (testing "GOST 3412-2015 encryption in CBC mode is successful"
    (let [secret-key        (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          algo-params       (IvParameterSpec. test-iv-16)
          cipher            (sut/new-encryption-cipher secret-key :cbc-mode algo-params)
          encrypted-bytes32 (sut/encrypt-bytes cipher (common/hex-to-bytes plain-32-hex))
          encrypted-bytes50 (sut/encrypt-bytes cipher (common/hex-to-bytes plain-50-hex))]
      (match (common/bytes-to-hex encrypted-bytes32) test-gost3412-2015-encrypted-bytes32-cbc)
      (match (common/bytes-to-hex encrypted-bytes50) test-gost3412-2015-encrypted-bytes50-cbc))))


(deftest ^:unit decrypt-bytes-test
  (testing "GOST 28147-89 decryption in CFB mode is successful"
    (let [secret-key        (sut/byte-array->secret-key test-secret-key sut/gost28147)
          iv                test-iv-8
          algo-params       (sut/init-gost-named-params sut/gost28147 iv "E-A")
          cipher            (sut/new-decryption-cipher secret-key :cfb-mode algo-params)
          decrypted-bytes32 (sut/decrypt-bytes cipher (common/hex-to-bytes test-gost28147-encrypted-bytes32-cfb))
          decrypted-bytes50 (sut/decrypt-bytes cipher (common/hex-to-bytes test-gost28147-encrypted-bytes50-cfb))]
      (match (common/bytes-to-hex decrypted-bytes32) plain-32-hex)
      (match (common/bytes-to-hex decrypted-bytes50) plain-50-hex)))

  (testing "GOST 28147-89 decryption in CTR mode is successful"
    (let [secret-key        (sut/byte-array->secret-key test-secret-key sut/gost28147)
          iv                test-iv-8
          algo-params       (sut/init-gost-named-params sut/gost28147 iv "E-A")
          cipher            (sut/new-decryption-cipher secret-key :ctr-mode algo-params)
          decrypted-bytes32 (sut/decrypt-bytes cipher (common/hex-to-bytes test-gost28147-encrypted-bytes32-ctr))
          decrypted-bytes50 (sut/decrypt-bytes cipher (common/hex-to-bytes test-gost28147-encrypted-bytes50-ctr))]
      (match (common/bytes-to-hex decrypted-bytes32) plain-32-hex)
      (match (common/bytes-to-hex decrypted-bytes50) plain-50-hex)))

  (testing "GOST 28147-89 decryption in CBC mode is successful"
    (let [secret-key        (sut/byte-array->secret-key test-secret-key sut/gost28147)
          iv                test-iv-8
          algo-params       (sut/init-gost-named-params sut/gost28147 iv "E-A")
          cipher            (sut/new-decryption-cipher secret-key :cbc-mode algo-params)
          decrypted-bytes32 (sut/decrypt-bytes cipher (common/hex-to-bytes test-gost28147-encrypted-bytes32-cbc))
          decrypted-bytes50 (sut/decrypt-bytes cipher (common/hex-to-bytes test-gost28147-encrypted-bytes50-cbc))]
      (match (common/bytes-to-hex decrypted-bytes32) plain-32-hex)
      (match (common/bytes-to-hex decrypted-bytes50) plain-50-hex)))


  (testing "GOST 3412-2015 decryption in CFB mode is successful"
    (let [secret-key        (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          algo-params       (IvParameterSpec. test-iv-16)
          cipher            (sut/new-decryption-cipher secret-key :cfb-mode algo-params)
          decrypted-bytes32 (sut/decrypt-bytes cipher (common/hex-to-bytes test-gost3412-2015-encrypted-bytes32-cfb))
          decrypted-bytes50 (sut/decrypt-bytes cipher (common/hex-to-bytes test-gost3412-2015-encrypted-bytes50-cfb))]
      (match (common/bytes-to-hex decrypted-bytes32) plain-32-hex)
      (match (common/bytes-to-hex decrypted-bytes50) plain-50-hex)))

  (testing "GOST 3412-2015 decryption in CTR mode is successful"
    (let [secret-key        (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          algo-params       (IvParameterSpec. test-iv-8)
          cipher            (sut/new-decryption-cipher secret-key :ctr-mode algo-params)
          decrypted-bytes32 (sut/decrypt-bytes cipher (common/hex-to-bytes test-gost3412-2015-encrypted-bytes32-ctr))
          decrypted-bytes50 (sut/decrypt-bytes cipher (common/hex-to-bytes test-gost3412-2015-encrypted-bytes50-ctr))]
      (match (common/bytes-to-hex decrypted-bytes32) plain-32-hex)
      (match (common/bytes-to-hex decrypted-bytes50) plain-50-hex)))

  (testing "GOST 3412-2015 decryption in CBC mode is successful"
    (let [secret-key        (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          algo-params       (IvParameterSpec. test-iv-16)
          cipher            (sut/new-decryption-cipher secret-key :cbc-mode algo-params)
          decrypted-bytes32 (sut/decrypt-bytes cipher (common/hex-to-bytes test-gost3412-2015-encrypted-bytes32-cbc))
          decrypted-bytes50 (sut/decrypt-bytes cipher (common/hex-to-bytes test-gost3412-2015-encrypted-bytes50-cbc))]
      (match (common/bytes-to-hex decrypted-bytes32) plain-32-hex)
      (match (common/bytes-to-hex decrypted-bytes50) plain-50-hex))))



(deftest ^:unit compress-bytes-test
  (testing "Compress bytes array is successful"
    (let [plain-string     (apply str (repeat 30 "A"))
          compressed-bytes (sut/compress-bytes (.getBytes plain-string))]
      (match (count compressed-bytes) 11)
      (is (< (count compressed-bytes) (.length plain-string))))))


(deftest ^:unit decompress-bytes-test
  (testing "Decompress bytes array is successful"
    (let [plain-string            (apply str (repeat 30 "A"))
          compressed-string-bytes (sut/compress-bytes (.getBytes plain-string))
          decompressed-string     (String. (sut/decompress-bytes compressed-string-bytes))
          compressed-bytes32      (sut/compress-bytes (.getBytes plain-32))
          decompressed-bytes32    (sut/decompress-bytes compressed-bytes32)
          compressed-bytes50      (sut/compress-bytes (.getBytes plain-50))
          decompressed-bytes50    (sut/decompress-bytes compressed-bytes50)]
      (match decompressed-string plain-string)
      (match (String. decompressed-bytes32) plain-32)
      (match (String. decompressed-bytes50) plain-50))))


(defn slurp-bytes
  "Slurp the bytes from a slurpable thing"
  ^bytes
  [x]
  (with-open [out (ByteArrayOutputStream.)]
    (io/copy (io/input-stream x) out)
    (.toByteArray out)))


(deftest ^:unit encrypt-stream-test

  (testing "GOST 28147-89 CFB mode encryption of byte array as a stream to output stream is successful. "
    (let [secret-key      (sut/byte-array->secret-key test-secret-key sut/gost28147)
          iv              test-iv-8
          algo-params     (sut/init-gost-named-params sut/gost28147 iv "E-A")
          cipher          (sut/new-encryption-cipher secret-key :cfb-mode algo-params)
          output-file     (File/createTempFile "gost-" ".txt")
          _               (.deleteOnExit output-file)
          _               (sut/encrypt-stream cipher (.getBytes plain-32) output-file)
          encrypted-bytes (slurp-bytes output-file)]
      (match (common/bytes-to-hex encrypted-bytes) test-gost28147-encrypted-bytes32-cfb)))

  (testing "GOST 3412-2015 CFB mode encryption of input stream to output stream is successful. "
    (let [secret-key      (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          algo-params     (IvParameterSpec. test-iv-16)
          cipher          (sut/new-encryption-cipher secret-key :cfb-mode algo-params)
          input-file      (File/createTempFile "plain-" ".txt")
          _               (.deleteOnExit input-file)
          _               (spit input-file plain-32)
          output-file     (File/createTempFile "gost-" ".txt")
          _               (.deleteOnExit output-file)
          _               (sut/encrypt-stream cipher input-file output-file)
          encrypted-bytes (slurp-bytes output-file)]
      (match (common/bytes-to-hex encrypted-bytes) test-gost3412-2015-encrypted-bytes32-cfb))))


(deftest ^:unit decrypt-stream-test

  (testing "GOST 28147-89 CFB mode decryption of byte array as a stream to output stream is successful. "
    (let [secret-key      (sut/byte-array->secret-key test-secret-key sut/gost28147)
          iv              test-iv-8
          algo-params     (sut/init-gost-named-params sut/gost28147 iv "E-A")
          cipher          (sut/new-decryption-cipher secret-key :cfb-mode algo-params)
          output-file     (File/createTempFile "plain-" ".txt")
          _               (.deleteOnExit output-file)
          _               (sut/decrypt-stream cipher (common/hex-to-bytes test-gost28147-encrypted-bytes32-cfb) output-file)
          decrypted-bytes (slurp-bytes output-file)]
      (match (String. ^bytes decrypted-bytes) plain-32)))

  (testing "GOST 3412-2015 CFB mode decryption of input stream to output stream is successful. "
    (let [secret-key  (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          algo-params (IvParameterSpec. test-iv-16)
          cipher      (sut/new-decryption-cipher secret-key :cfb-mode algo-params)
          input-file  (File/createTempFile "gost-" ".txt")
          _           (.deleteOnExit input-file)
          _           (with-open [out (io/output-stream input-file)]
                        (.write out ^bytes (common/hex-to-bytes test-gost3412-2015-encrypted-bytes32-cfb)))
          output-file (File/createTempFile "plain-" ".txt")
          _           (.deleteOnExit output-file)
          _           (sut/decrypt-stream cipher input-file output-file)
          plain-bytes (slurp output-file)]
      (match plain-bytes plain-32))))


(deftest ^:unit compress-stream-test
  (testing "Compress bytes array as input stream to output stream is successful"
    (let [plain-string     (apply str (repeat 30 "A"))
          output-file      (File/createTempFile "zip-" ".txt")
          _                (.deleteOnExit output-file)
          _                (sut/compress-stream (.getBytes plain-string) output-file)
          compressed-bytes (slurp-bytes output-file)]
      (match (count compressed-bytes) 11)
      (is (< (count compressed-bytes) (.length plain-string)))))

  (testing "Compress input stream to output stream is successful"
    (let [plain-string     (apply str (repeat 30 "A"))
          input-file       (File/createTempFile "plain-" ".txt")
          _                (.deleteOnExit input-file)
          _                (with-open [out (io/output-stream input-file)]
                             (.write out ^bytes (.getBytes plain-string)))
          output-file      (File/createTempFile "zip-" ".txt")
          _                (.deleteOnExit output-file)
          _                (sut/compress-stream input-file output-file)
          compressed-bytes (slurp-bytes output-file)]
      (match (count compressed-bytes) 11)
      (is (< (count compressed-bytes) (.length plain-string))))))


(deftest ^:unit decompress-stream-test
  (testing "Decompress bytes array as input stream to output stream is successful"
    (let [plain-string        (apply str (repeat 30 "A"))
          compressed-bytes    (sut/compress-bytes (.getBytes plain-string))
          output-file         (File/createTempFile "plain-" ".txt")
          _                   (.deleteOnExit output-file)
          _                   (sut/decompress-stream compressed-bytes output-file)
          decompressed-string (slurp output-file)]
      (match decompressed-string plain-string)))

  (testing "Decompress input stream to output stream is successful"
    (let [plain-string        (apply str (repeat 30 "A"))
          compressed-bytes    (sut/compress-bytes (.getBytes plain-string))
          input-file          (File/createTempFile "zip-" ".txt")
          _                   (.deleteOnExit input-file)
          _                   (with-open [out (io/output-stream input-file)]
                                (.write out ^bytes compressed-bytes))
          output-file         (File/createTempFile "plain-" ".txt")
          _                   (.deleteOnExit output-file)
          _                   (sut/decompress-stream input-file output-file)
          decompressed-string (slurp output-file)]
      (match decompressed-string plain-string))))


(deftest ^:unit compress-and-encrypt-stream-test
  (testing "Data stream is compressed and then encrypted with GOST 28147-89 in CFB mode"
    (let [n                              300
          plain-string                   (apply str (repeat n "A"))

          ;; encrypt and compress
          secret-key                     (sut/byte-array->secret-key test-secret-key sut/gost28147)
          iv                             test-iv-8
          algo-params                    (sut/init-gost-named-params sut/gost28147 iv "E-A")
          cipher                         (sut/new-encryption-cipher secret-key :cfb-mode algo-params)
          baos1                          (ByteArrayOutputStream.)
          _                              (sut/compress-and-encrypt-stream cipher (.getBytes plain-string) baos1)
          compressed-and-encrypted-bytes (.toByteArray baos1)

          ;; decrypt
          algo-params2                   (sut/init-gost-named-params sut/gost28147 iv "E-A")
          cipher2                        (sut/new-decryption-cipher secret-key :cfb-mode algo-params2)
          decrypted-but-compressed-bytes (sut/decrypt-bytes cipher2 compressed-and-encrypted-bytes)

          ;; decompress
          uncompressed-bytes             (sut/decompress-bytes decrypted-but-compressed-bytes)]
      (match (count compressed-and-encrypted-bytes) 13)
      (match (count decrypted-but-compressed-bytes) 13)
      (match (count uncompressed-bytes) n)))

  (testing "Data stream is compressed and then encrypted with GOST 3412-2015 in CFB mode"
    (let [n                              300
          plain-string                   (apply str (repeat n "A"))

          ;; encrypt and compress
          secret-key                     (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          algo-params                    (IvParameterSpec. test-iv-16)
          cipher                         (sut/new-encryption-cipher secret-key :cfb-mode algo-params)
          baos1                          (ByteArrayOutputStream.)
          _                              (sut/compress-and-encrypt-stream cipher (.getBytes plain-string) baos1)
          compressed-and-encrypted-bytes (.toByteArray baos1)

          ;; decrypt
          algo-params2                   (IvParameterSpec. test-iv-16)
          cipher2                        (sut/new-decryption-cipher secret-key :cfb-mode algo-params2)
          decrypted-but-compressed-bytes (sut/decrypt-bytes cipher2 compressed-and-encrypted-bytes)

          ;; decompress
          uncompressed-bytes             (sut/decompress-bytes decrypted-but-compressed-bytes)]
      (match (count compressed-and-encrypted-bytes) 13)
      (match (count decrypted-but-compressed-bytes) 13)
      (match (count uncompressed-bytes) n))))


(deftest ^:unit decrypt-and-decompress-stream-test
  (testing "Data stream is decrypted and then decompressed with GOST 28147-89 in CFB mode"
    (let [plain-file   (io/file "test/data/big.txt")
          ;; encrypt and compress
          secret-key   (sut/byte-array->secret-key test-secret-key sut/gost28147)
          iv           test-iv-8
          algo-params  (sut/init-gost-named-params sut/gost28147 iv "E-A")
          cipher       (sut/new-encryption-cipher secret-key :cfb-mode algo-params)
          output-file  (File/createTempFile "gost-" ".txt")
          _            (.deleteOnExit output-file)
          _            (sut/compress-and-encrypt-stream cipher plain-file output-file)

          ;; decrypt and decompress
          algo-params2 (sut/init-gost-named-params sut/gost28147 iv "E-A")
          cipher2      (sut/new-decryption-cipher secret-key :cfb-mode algo-params2)
          output-file2 (File/createTempFile "plain-" ".txt")
          _            (.deleteOnExit output-file2)
          _            (sut/decrypt-and-decompress-stream cipher2 output-file output-file2)]
      (is (> (.length plain-file) 0))
      (is (> (.length plain-file) (.length ^File output-file)))
      (is (= (.length plain-file) (.length ^File output-file2)))))

  (testing "Data stream is decrypted and then decompressed with GOST 3412-2015 in CTR mode"
    (let [plain-file   (io/file "test/data/big.txt")
          ;; encrypt and compress
          secret-key   (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          algo-params  (IvParameterSpec. test-iv-8)
          cipher       (sut/new-encryption-cipher secret-key :ctr-mode algo-params)
          output-file  (File/createTempFile "gost-" ".txt")
          _            (.deleteOnExit output-file)
          _            (sut/compress-and-encrypt-stream cipher plain-file output-file)

          ;; decrypt and decompress
          algo-params2 (IvParameterSpec. test-iv-8)
          cipher2      (sut/new-decryption-cipher secret-key :ctr-mode algo-params2)
          output-file2 (File/createTempFile "plain-" ".txt")
          _            (.deleteOnExit output-file2)
          _            (sut/decrypt-and-decompress-stream cipher2 output-file output-file2)]
      (is (> (.length plain-file) 0))
      (is (> (.length plain-file) (.length ^File output-file)))
      (is (= (.length plain-file) (.length ^File output-file2))))))


(deftest ^:unit mac-3412-stream-test

  (testing "Calculate MAC for input stream using GOST 3412-2015 is successful"
    (let [secret-key  (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          mac-bytes32 (sut/mac-3412-stream secret-key (.getBytes plain-32))
          mac-bytes50 (sut/mac-3412-stream secret-key (.getBytes plain-50))]
      (match test-mac-gost3412-2015-plain-32 (common/bytes-to-hex mac-bytes32))
      (match test-mac-gost3412-2015-plain-50 (common/bytes-to-hex mac-bytes50)))))


(deftest ^:unit mac-28147-stream-test
  (testing "Calculate MAC for input stream using GOST 28147-89 is successful"
    (let [secret-key  (sut/byte-array->secret-key test-secret-key sut/gost28147)
          mac-bytes32 (sut/mac-28147-stream secret-key (.getBytes plain-32))
          mac-bytes50 (sut/mac-28147-stream secret-key (.getBytes plain-50))]
      (match test-mac-gost28147-plain-32 (common/bytes-to-hex mac-bytes32))
      (match test-mac-gost28147-plain-50 (common/bytes-to-hex mac-bytes50)))))


(deftest ^:unit mac-stream-test

  (testing "MAC in stream mode is calculated successful"
    (let [secret-key-2015 (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          secret-key-89   (sut/byte-array->secret-key test-secret-key sut/gost28147)
          mac-big-2015    (sut/mac-stream secret-key-2015 "test/data/big.txt")
          mac-big-89      (sut/mac-stream secret-key-89 "test/data/big.txt")]
      (match test-mac-gost3412-2015-big-txt (common/bytes-to-hex mac-big-2015))
      (match test-mac-gost28147-big-txt (common/bytes-to-hex mac-big-89)))))


(deftest ^:unit iv-length-by-algo-mode-test
  (testing "Check IV length in tests"
    (let [result1 (sut/iv-length-by-algo-mode "" :ctr-mode)
          result2 (sut/iv-length-by-algo-mode sut/gost28147 :cbc-mode)
          result3 (sut/iv-length-by-algo-mode sut/gost28147 :cfb-mode)
          result4 (sut/iv-length-by-algo-mode sut/gost3412-2015 :cbc-mode)
          result5 (sut/iv-length-by-algo-mode sut/gost3412-2015 :cfb-mode)]
      (match result1 8)
      (match result2 8)
      (match result3 8)
      (match result4 16)
      (match result5 16))))


(deftest ^:unit protect-bytes-test
  (testing "Protect/unprotect success for plain-32"
    (let [plain-data            plain-32
          secret-key-2015       (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          secret-key-89         (sut/byte-array->secret-key test-secret-key sut/gost28147)
          protected-data-2015   (sut/protect-bytes secret-key-2015 (.getBytes plain-data))
          protected-data-89     (sut/protect-bytes secret-key-89 (.getBytes plain-data))
          unprotected-data-2015 (sut/unprotect-bytes secret-key-2015 protected-data-2015)
          unprotected-data-89   (sut/unprotect-bytes secret-key-89 protected-data-89)]
      (match (String. ^bytes unprotected-data-2015) plain-data)
      (match (String. ^bytes unprotected-data-89) plain-data)))

  (testing "Protect/unprotect success for plain-50"
    (let [plain-data            plain-50
          secret-key-2015       (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          secret-key-89         (sut/byte-array->secret-key test-secret-key sut/gost28147)
          protected-data-2015   (sut/protect-bytes secret-key-2015 (.getBytes plain-data))
          protected-data-89     (sut/protect-bytes secret-key-89 (.getBytes plain-data))
          unprotected-data-2015 (sut/unprotect-bytes secret-key-2015 protected-data-2015)
          unprotected-data-89   (sut/unprotect-bytes secret-key-89 protected-data-89)]
      (match (String. ^bytes unprotected-data-2015) plain-data)
      (match (String. ^bytes unprotected-data-89) plain-data)))

  (testing "Protect/unprotect success for a big file"
    (let [plain-data            (slurp "test/data/big.txt")
          secret-key-2015       (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          secret-key-89         (sut/byte-array->secret-key test-secret-key sut/gost28147)
          protected-data-2015   (sut/protect-bytes secret-key-2015 (.getBytes plain-data))
          protected-data-89     (sut/protect-bytes secret-key-89 (.getBytes plain-data))
          unprotected-data-2015 (sut/unprotect-bytes secret-key-2015 protected-data-2015)
          unprotected-data-89   (sut/unprotect-bytes secret-key-89 protected-data-89)]
      (match (String. ^bytes unprotected-data-2015) plain-data)
      (match (String. ^bytes unprotected-data-89) plain-data))))



(deftest ^:unit unprotect-bytes-test

  (testing "Protect/unprotect fails if mac is corrupted"
    (let [plain-data          plain-50
          secret-key-2015     (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          secret-key-89       (sut/byte-array->secret-key test-secret-key sut/gost28147)
          protected-data-2015 (sut/protect-bytes secret-key-2015 (.getBytes plain-data))
          protected-data-89   (sut/protect-bytes secret-key-89 (.getBytes plain-data))

          corrupted-data-2015 (byte-array (update (into [] protected-data-2015) sut/iv-length-16 inc))
          corrupted-data-89   (byte-array (update (into [] protected-data-89) sut/iv-length-8 inc))]

      (is (thrown-with-msg? ExceptionInfo #"Decrypted data is corrupted: Mac codes are different"
            (sut/unprotect-bytes secret-key-2015 corrupted-data-2015)))

      (is (thrown-with-msg? ExceptionInfo #"Decrypted data is corrupted: Mac codes are different"
            (sut/unprotect-bytes secret-key-89 corrupted-data-89))))))


(deftest ^:unit protect-file-test

  (testing "Protect/unprotect-file success for a big file"
    (let [input-filename           "test/data/big.txt"
          secret-key-2015          (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          secret-key-89            (sut/byte-array->secret-key test-secret-key sut/gost28147)

          output-file-enc-2015     (File/createTempFile "filename" ".enc")
          output-file-enc-89       (File/createTempFile "filename" ".enc")
          _                        (.deleteOnExit output-file-enc-2015)
          _                        (.deleteOnExit output-file-enc-89)

          output-filename-enc-2015 (.getAbsolutePath output-file-enc-2015)
          output-filename-enc-89   (.getAbsolutePath output-file-enc-89)

          _                        (sut/protect-file secret-key-2015 input-filename output-filename-enc-2015)
          _                        (sut/protect-file secret-key-89 input-filename output-filename-enc-89)

          output-file-txt-2015     (File/createTempFile "filename" ".txt")
          output-file-txt-89       (File/createTempFile "filename" ".txt")
          _                        (.deleteOnExit output-file-txt-2015)
          _                        (.deleteOnExit output-file-txt-89)

          _                        (sut/unprotect-file secret-key-2015 output-file-enc-2015 output-file-txt-2015)
          _                        (sut/unprotect-file secret-key-89 output-file-enc-89 output-file-txt-89)
          input-content            (slurp input-filename)]

      (match input-content (slurp output-file-txt-2015))
      (match input-content (slurp output-file-txt-89))

      (.delete (io/file output-filename-enc-2015))
      (.delete (io/file output-filename-enc-89))
      (.delete (io/file output-file-txt-2015))
      (.delete (io/file output-file-txt-89)))))



(deftest ^:unit unprotect-file-test

  (testing "Protect/unprotect-file unsuccessful for corrupted data"
    (let [input-filename           "test/data/big.txt"
          secret-key-2015          (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          secret-key-89            (sut/byte-array->secret-key test-secret-key sut/gost28147)

          output-file-enc-2015     (File/createTempFile "filename" ".enc")
          output-file-enc-89       (File/createTempFile "filename" ".enc")
          _                        (.deleteOnExit output-file-enc-2015)
          _                        (.deleteOnExit output-file-enc-89)

          output-filename-enc-2015 (.getAbsolutePath output-file-enc-2015)
          output-filename-enc-89   (.getAbsolutePath output-file-enc-89)

          _                        (sut/protect-file secret-key-2015 input-filename output-filename-enc-2015)
          _                        (sut/protect-file secret-key-89 input-filename output-filename-enc-89)

          output-file-txt-2015     (File/createTempFile "filename" ".txt")
          output-file-txt-89       (File/createTempFile "filename" ".txt")
          _                        (.deleteOnExit output-file-txt-2015)
          _                        (.deleteOnExit output-file-txt-89)

          protected-data-2015      (byte-array (.length output-file-enc-2015))
          protected-data-89        (byte-array (.length output-file-enc-89))
          in-2015                  (io/input-stream output-file-enc-2015)
          in-89                    (io/input-stream output-file-enc-89)
          _                        (.read in-2015 protected-data-2015)
          _                        (.read in-89 protected-data-89)

          corrupted-data-2015      (byte-array (update (into [] protected-data-2015) sut/iv-length-16 inc))
          corrupted-data-89        (byte-array (update (into [] protected-data-89) sut/iv-length-8 inc))

          out-2015                 (io/output-stream output-filename-enc-2015)
          out-89                   (io/output-stream output-filename-enc-89)

          _                        (.write out-2015 corrupted-data-2015)
          _                        (.write out-89 corrupted-data-89)]

      (is (thrown-with-msg? ExceptionInfo #"Decrypted data is corrupted: Mac codes are different"
            (sut/unprotect-file secret-key-2015 output-file-enc-2015 output-file-txt-2015)))

      (is (thrown-with-msg? ExceptionInfo #"Decrypted data is corrupted: Mac codes are different"
            (sut/unprotect-file secret-key-89 output-file-enc-89 output-file-txt-89)))

      (.delete (io/file output-filename-enc-2015))
      (.delete (io/file output-filename-enc-89))
      (.delete (io/file output-file-txt-2015))
      (.delete (io/file output-file-txt-89)))))


(comment

  ;; example of data compression and encryption
  (sut/compress-stream "LICENSE" "LICENSE.zip1")

  (def secret-key (sut/byte-array->secret-key test-secret-key sut/gost3412-2015))
  (def algo-params (IvParameterSpec. test-iv-16))
  (def cipher (sut/new-encryption-cipher secret-key :cfb-mode algo-params))
  (sut/compress-and-encrypt-stream cipher "LICENSE" "LICENSE.gost")

  (def algo-params2 (IvParameterSpec. test-iv-16))
  (def cipher2 (sut/new-decryption-cipher secret-key :cfb-mode algo-params2))
  (sut/decrypt-stream cipher2 "LICENSE.gost" "LICENSE.zip2")
  (sut/decompress-stream "LICENSE.zip2" "LICENSE2")

  (def algo-params3 (IvParameterSpec. test-iv-16))
  (def cipher3 (sut/new-decryption-cipher secret-key :cfb-mode algo-params3))
  (sut/decrypt-and-decompress-stream cipher3 "LICENSE.gost" "LICENSE3"))


(comment

  ;; Example of using stream encryption via Socket

  (import '(java.net ServerSocket Socket SocketException)
    '(java.io InputStreamReader))

  (defn new-thread [f]
    (doto (Thread. f) (.start)))

  (defn encrypt-socket-stream
    "Compress and encrypt input-stream and write encrypted bytes to output-stream"
    [input-stream output-stream]
    (let [secret-key  (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          algo-params (IvParameterSpec. test-iv-16)
          cipher      (sut/new-encryption-cipher secret-key :cfb-mode algo-params)
          o           (io/output-stream output-stream)
          _           (.write o (.getBytes "Enter plain text and press <Enter>:\n"))
          _           (.flush o)
          s           (.readLine (BufferedReader. (InputStreamReader. input-stream)))
          baos        (ByteArrayOutputStream.)]
      (sut/compress-and-encrypt-stream cipher (.getBytes s) baos)
      (.write o (.getBytes (common/bytes-to-hex (.toByteArray baos))))
      (.write o (.getBytes "\n"))
      (.flush o)
      (.close input-stream)
      (.close output-stream)))

  (defn decrypt-socket-stream
    "Decrypt and decompress input-stream and write plain bytes to output-stream"
    [input-stream output-stream]
    (let [secret-key  (sut/byte-array->secret-key test-secret-key sut/gost3412-2015)
          algo-params (IvParameterSpec. test-iv-16)
          cipher      (sut/new-decryption-cipher secret-key :cfb-mode algo-params)
          o           (io/output-stream output-stream)
          _           (.write o (.getBytes "Enter hex encrypted bytes text and press <Enter>:\n"))
          _           (.flush o)
          s           (.readLine (BufferedReader. (InputStreamReader. input-stream)))
          baos        (ByteArrayOutputStream.)]
      (sut/decrypt-and-decompress-stream cipher (common/hex-to-bytes s) baos)
      (.write o (.toByteArray baos))
      (.write o (.getBytes "\n"))
      (.flush o)
      (.close input-stream)
      (.close output-stream)))

  (defn accept-server-encrypt-fn
    "Starts a thread on the iostreams of supplied socket"
    [^Socket socket]
    (new-thread
      #(encrypt-socket-stream
         (.getInputStream socket)
         (.getOutputStream socket))))

  (defn accept-server-decrypt-fn
    "Starts a thread on the iostreams of supplied socket"
    [^Socket socket]
    (new-thread
      #(decrypt-socket-stream
         (.getInputStream socket)
         (.getOutputStream socket))))

  (defn create-server
    "creates and returns a server socket on port, will pass the client
    socket to accept-socket function on connection"
    [accept-socket-fn port]
    (let [server-socket (ServerSocket. port)]
      (new-thread #(when-not (.isClosed server-socket)
                     (try
                       (accept-socket-fn (.accept server-socket))
                       (catch SocketException e
                         (println "Server socket exception:" (.getMessage e))))
                     (recur)))
      server-socket))

  (def encrypt-server (create-server accept-server-encrypt-fn 13581))
  ;; then: 'nc localhost 13581'    to compress and encrypt
  ;; to stop play close server
  (.close encrypt-server)

  (def decrypt-server (create-server accept-server-decrypt-fn 13580))
  ;; then: 'nc localhost 13580'     to decrypt and decompress
  ;; to stop play close server
  (.close decrypt-server)

  )





