(ns org.rssys.gost.digest-test
  (:require
    [clojure.test :as test :refer [deftest is testing]]
    [matcho.core :refer [match]]
    [org.rssys.gost.common :as common]
    [org.rssys.gost.digest :as sut])
  (:import
    (org.bouncycastle.crypto.digests
      GOST3411_2012_256Digest
      GOST3411_2012_512Digest)))


;; Test S-box from GOST standard. Should NEVER be used in production!!!
;; See https://datatracker.ietf.org/doc/html/rfc4357#section-11.2
;; Sequence id-GostR3411-94-TestParamSet
(def test-s-box
  [4 10 9 2 13 8 0 14 6 11 1 12 7 15 5 3
   14 11 4 12 6 13 15 10 2 3 8 1 0 7 5 9
   5 8 1 13 10 3 4 2 14 15 12 7 6 0 9 11
   7 13 10 1 0 8 9 15 14 4 6 12 11 2 5 3
   6 12 7 1 5 15 13 8 4 10 9 14 0 3 11 2
   4 11 10 0 7 2 1 13 3 6 8 5 9 12 15 14
   13 11 4 1 3 15 5 9 0 10 14 7 6 8 2 12
   1 15 13 0 5 7 10 4 9 2 3 14 6 11 8 12])


(def m1 "")
(def m2 "The quick brown fox jumps over the lazy dog")
(def m3 "Suppose the original message has length = 50 bytes")
(def m4 "This is message, length=32 bytes")


(deftest digest-stream-test

  ;; See https://ru.wikipedia.org/wiki/ГОСТ_Р_34.11-94
  (testing "GOST3411-94 engine with test S-box params produces correct digest value"
    (let [engine (sut/-gost-3411 (byte-array test-s-box))
          r1     (sut/digest-stream (.getBytes m1) :digest-class engine)
          r2     (sut/digest-stream (.getBytes m2) :digest-class engine)
          r3     (sut/digest-stream (.getBytes m3) :digest-class engine)
          r4     (sut/digest-stream (.getBytes m4) :digest-class engine)]
      (match (common/bytes-to-hex r1) "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d")
      (match (common/bytes-to-hex r2) "77b7fa410c9ac58a25f49bca7d0468c9296529315eaca76bd1a10f376d1f4294")
      (match (common/bytes-to-hex r3) "471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208")
      (match (common/bytes-to-hex r4) "b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa")))

  ;; See https://ru.wikipedia.org/wiki/ГОСТ_Р_34.11-94
  (testing "GOST3411-94 engine with default CryptoPro S-box params produces correct digest value"
    (let [engine (sut/-gost-3411)
          r1     (sut/digest-stream (.getBytes m1) :digest-class engine)
          r2     (sut/digest-3411-94 (.getBytes m2))
          r3     (sut/digest-stream (.getBytes m3) :digest-class engine)
          r4     (sut/digest-3411-94 (.getBytes m4))]
      (match (common/bytes-to-hex r1) "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0")
      (match (common/bytes-to-hex r2) "9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76")
      (match (common/bytes-to-hex r3) "c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011")
      (match (common/bytes-to-hex r4) "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb")))

  ;; See digests 3411-2012-256  https://en.wikipedia.org/wiki/Streebog
  ;; also http://www.netlab.linkpc.net/download/software/SDK/core/include/gost3411-2012.h
  (testing "GOST3411-2012-256 engine produces correct digest value"
    (let [engine (GOST3411_2012_256Digest.)
          r1     (sut/digest-stream (.getBytes m1) :digest-class engine)
          r2     (sut/digest-2012-256 (.getBytes m2))
          r3     (sut/digest-stream (.getBytes m3) :digest-class engine)
          r4     (sut/digest-2012-256 (.getBytes m4))]
      (match (common/bytes-to-hex r1) "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb")
      (match (common/bytes-to-hex r2) "3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4")
      (match (common/bytes-to-hex r3) "a3ed85322e1a1479b605a752b1d487fd138863aa1ea67a91e157aa53fce796f3")
      (match (common/bytes-to-hex r4) "6fa8592b1cd28ca72d87e7d413d8b3de31077098bed3818d98f6f79bac5cc645")))

  ;; See digests 3411-2012-256  https://en.wikipedia.org/wiki/Streebog
  ;; also http://www.netlab.linkpc.net/download/software/SDK/core/include/gost3411-2012.h
  (testing "GOST3411-2012-512 engine produces correct digest value"
    (let [engine (GOST3411_2012_512Digest.)
          r1     (sut/digest-stream (.getBytes m1) :digest-class engine)
          r2     (sut/digest-2012-512 (.getBytes m2))
          r3     (sut/digest-stream (.getBytes m3) :digest-class engine)
          r4     (sut/digest-2012-512 (.getBytes m4))]
      (match (common/bytes-to-hex r1) "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a")
      (match (common/bytes-to-hex r2) "d2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b97e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe")
      (match (common/bytes-to-hex r3) "275557a47dcfcb8235ff029b74837f0441efe41aed12c207313e83b27abd1e6a9d892713bc30a16bf947d46a59bbbb3a33ee33385391c73675e7d0c360213540")
      (match (common/bytes-to-hex r4) "eeb2c35b760457d290022fc060e29500122ccdbd73b834ec04048d6de75e942fc52df86fa0ddddfce882b8dbda573ffba0232903c4c057b76624962809c184bf")))

  (testing "Digest generated for a file has correct value"
    (let [input   "test/data/plain32.txt"
          result  (sut/digest-2012-256 input)
          result2 (sut/digest-2012-256 (.getBytes m4))]
      (match (common/bytes-to-hex result) "6fa8592b1cd28ca72d87e7d413d8b3de31077098bed3818d98f6f79bac5cc645")
      (match (common/bytes-to-hex result2) "6fa8592b1cd28ca72d87e7d413d8b3de31077098bed3818d98f6f79bac5cc645")
      (match m4 (slurp input)))))


(deftest hmac-stream-test

  (testing "HMAC for the same data and the same secret key are always the same"
    (let [secret-key (byte-array [0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1])
          r1         (sut/hmac-3411-94 (.getBytes m2) secret-key)
          r2         (sut/hmac-2012-256 (.getBytes m2) secret-key)
          r3         (sut/hmac-2012-512 (.getBytes m2) secret-key)]
      (match (common/bytes-to-hex r1) "3c5b39f1b9b22a0b76516796e2bd663d7adccb86ecf2d361ebd87eacb9a60953")
      (match (common/bytes-to-hex r2) "8eeb292527987200713fcae90041c5abf91759e6cb94c7e72b2d6a9827f66f26")
      (match (common/bytes-to-hex r3) "5f6d6e56f39c8ad9a6cde18b46e51336f4cc20ae8916915e031ce2307c3c0c452cabe60eb1530f3f7088c93de37252b4f4c023a7cd635848c60d1fb48cb1b0e9")))

  (testing "HMAC for the same data and the other secret key are always different"
    (let [secret-key-2 (byte-array [1 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1])
          r1           (sut/hmac-3411-94 (.getBytes m2) secret-key-2)
          r2           (sut/hmac-2012-256 (.getBytes m2) secret-key-2)
          r3           (sut/hmac-2012-512 (.getBytes m2) secret-key-2)]
      (match (common/bytes-to-hex r1) "b3d8070b2b585b8c8e27e87b48e1e24012352aa890506a0cbeb764be9bacd660")
      (match (common/bytes-to-hex r2) "f9d56fedcea1272344f1313ff2e52ded04fd296bffd6c1a1118d750dd6513534")
      (match (common/bytes-to-hex r3) "1c1a16309b4389fb9cbc660069104197e0d542c3f734412ab4d7d86cdf52f70fc9b875710318600e1182185d4c0a35bf62f10ca13ce3cd4c5f02f5baa6b9a66e")))

  (testing "HMAC for the other data and the same secret key are always different"
    (let [secret-key (byte-array [0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1])
          r1         (sut/hmac-3411-94 (.getBytes (str m2 "1")) secret-key)
          r2         (sut/hmac-2012-256 (.getBytes (str m2 "1")) secret-key)
          r3         (sut/hmac-2012-512 (.getBytes (str m2 "1")) secret-key)]
      (match (common/bytes-to-hex r1) "1a901866e12dcc6357a6468ad8a54793bf13da13f7f2985d8fbeab1d19283301")
      (match (common/bytes-to-hex r2) "2980fa8f6cbd703257790983315d3dd04709e831bd422f222d9e3302526ffc60")
      (match (common/bytes-to-hex r3) "9efa1a55a33f36156b5126eb40616d000cf2edaa0491392524cb3e2849e3f235bf5c24a9bdf36758ea1644b1f4496e00afad5d6b2466d6fe6971613103aed003"))))
