use "pony_test"
use "pony_check"

actor \nodoc\ Main is TestList
  new create(env: Env) => PonyTest(env, this)
  new make() => None

  fun tag tests(test: PonyTest) =>
    test(_TestConstantTimeCompare)
    test(_TestMD4)
    test(_TestMD5)
    test(_TestRIPEMD160)
    test(_TestSHA1)
    test(_TestSHA224)
    test(_TestSHA256)
    test(_TestSHA384)
    test(_TestSHA512)
    test(_TestDigest)
    test(_TestHmacSha256Rfc4231)
    test(_TestHmacSha256Scram)
    test(_TestRandBytes)
    test(Property1UnitTest[USize](_TestHmacSha256OutputLength))
    test(Property1UnitTest[USize](_TestHmacSha256Deterministic))
    test(Property1UnitTest[USize](_TestRandBytesOutputLength))
    test(Property1UnitTest[USize](_TestRandBytesNonConstant))
    ifdef "openssl_1.1.x" or "openssl_3.0.x" or "libressl" then
      test(_TestPbkdf2Sha256Rfc7914)
      test(_TestPbkdf2Sha256Scram)
      test(Property1UnitTest[USize](_TestPbkdf2Sha256OutputLength))
      test(Property1UnitTest[USize](_TestPbkdf2Sha256Deterministic))
    end
    ifdef "openssl_3.0.x" then
      test(Property1UnitTest[USize](_TestShake128OutputLength))
      test(Property1UnitTest[USize](_TestShake256OutputLength))
      test(Property1UnitTest[USize](_TestShake128XofPrefix))
      test(Property1UnitTest[USize](_TestShake256XofPrefix))
    end

class \nodoc\ iso _TestConstantTimeCompare is UnitTest
  fun name(): String => "crypto/ConstantTimeCompare"

  fun apply(h: TestHelper) =>
    let s1 = "12345"
    let s2 = "54321"
    let s3 = "123456"
    let s4 = "1234"
    let s5 = recover val [as U8: 0; 0; 0; 0; 0] end
    let s6 = String.from_array([0; 0; 0; 0; 0])
    let s7 = ""
    h.assert_true(ConstantTimeCompare(s1, s1))
    h.assert_false(ConstantTimeCompare(s1, s2))
    h.assert_false(ConstantTimeCompare(s1, s3))
    h.assert_false(ConstantTimeCompare(s1, s4))
    h.assert_false(ConstantTimeCompare(s1, s5))
    h.assert_true(ConstantTimeCompare(s5, s6))
    h.assert_false(ConstantTimeCompare(s1, s6))
    h.assert_false(ConstantTimeCompare(s1, s7))

class \nodoc\ iso _TestMD4 is UnitTest
  fun name(): String => "crypto/MD4"

  fun apply(h: TestHelper) =>
    h.assert_eq[String](
      "db346d691d7acc4dc2625db19f9e3f52",
      ToHexString(MD4("test")))

class \nodoc\ iso _TestMD5 is UnitTest
  fun name(): String => "crypto/MD5"

  fun apply(h: TestHelper) =>
    h.assert_eq[String](
      "098f6bcd4621d373cade4e832627b4f6",
      ToHexString(MD5("test")))

class \nodoc\ iso _TestRIPEMD160 is UnitTest
  fun name(): String => "crypto/RIPEMD160"

  fun apply(h: TestHelper) =>
    h.assert_eq[String](
      "5e52fee47e6b070565f74372468cdc699de89107",
      ToHexString(RIPEMD160("test")))

class \nodoc\ iso _TestSHA1 is UnitTest
  fun name(): String => "crypto/SHA1"

  fun apply(h: TestHelper) =>
    h.assert_eq[String](
      "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
      ToHexString(SHA1("test")))

class \nodoc\ iso _TestSHA224 is UnitTest
  fun name(): String => "crypto/SHA224"

  fun apply(h: TestHelper) =>
    h.assert_eq[String](
      "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809",
      ToHexString(SHA224("test")))

class \nodoc\ iso _TestSHA256 is UnitTest
  fun name(): String => "crypto/SHA256"

  fun apply(h: TestHelper) =>
    h.assert_eq[String](
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      ToHexString(SHA256("test")))

class \nodoc\ iso _TestSHA384 is UnitTest
  fun name(): String => "crypto/SHA384"

  fun apply(h: TestHelper) =>
    h.assert_eq[String](
      "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4" +
      "b7ef1ccb126255d196047dfedf17a0a9",
      ToHexString(SHA384("test")))

class \nodoc\ iso _TestSHA512 is UnitTest
  fun name(): String => "crypto/SHA512"

  fun apply(h: TestHelper) =>
    h.assert_eq[String](
      "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db2" +
      "7ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff",
      ToHexString(SHA512("test")))

class \nodoc\ iso _TestDigest is UnitTest
  fun name(): String => "crypto/Digest"

  fun apply(h: TestHelper) ? =>
    let md5 = Digest.md5()
    md5.append("message1")?
    md5.append("message2")?
    h.assert_eq[String](
      "94af09c09bb9bb7b5c94fec6e6121482",
      ToHexString(md5.final()))

    let sha1 = Digest.sha1()
    sha1.append("message1")?
    sha1.append("message2")?
    h.assert_eq[String](
      "942682e2e49f37b4b224fc1aec1a53a25967e7e0",
      ToHexString(sha1.final()))

    let sha224 = Digest.sha224()
    sha224.append("message1")?
    sha224.append("message2")?
    h.assert_eq[String](
      "fbba013f116e8b09b044b2a785ed7fb6a65ce672d724c1fb20500d45",
      ToHexString(sha224.final()))

    let sha256 = Digest.sha256()
    sha256.append("message1")?
    sha256.append("message2")?
    h.assert_eq[String](
      "68d9b867db4bde630f3c96270b2320a31a72aafbc39997eb2bc9cf2da21e5213",
      ToHexString(sha256.final()))

    let sha384 = Digest.sha384()
    sha384.append("message1")?
    sha384.append("message2")?
    h.assert_eq[String](
      "7736dd67494a7072bf255852bd327406b398cb0b16cb400fcd3fcfb6827d74ab"+
      "9b14673d50515b6273ef15543325f8d3",
      ToHexString(sha384.final()))

    let sha512 = Digest.sha512()
    sha512.append("message1")?
    sha512.append("message2")?
    h.assert_eq[String](
      "3511f4825021a90cd55d37db5c3250e6bbcffc9a0d56d88b4e2878ac5b094692"+
      "cd945c6a77006272322f911c9be31fa970043daa4b61cee607566cbfa2c69b09",
      ToHexString(sha512.final()))

    ifdef "openssl_1.1.x" or "openssl_3.0.x" then
      let shake128 = Digest.shake128()
      shake128.append("message1")?
      shake128.append("message2")?
      h.assert_eq[String](
      "0d11671f23b6356bdf4ba8dcae37419d",
      ToHexString(shake128.final()))

      let shake256 = Digest.shake256()
      shake256.append("message1")?
      shake256.append("message2")?
      h.assert_eq[String](
      "80e2bbb14639e3b1fc1df80b47b67fb518b0ed26a1caddfa10d68f7992c33820",
      ToHexString(shake256.final()))
    end

class \nodoc\ iso _TestHmacSha256Rfc4231 is UnitTest
  """
  HMAC-SHA-256 test vectors from RFC 4231.
  """
  fun name(): String => "crypto/HmacSha256/RFC4231"

  fun apply(h: TestHelper) =>
    // Test Case 1: Key = 20 bytes of 0x0b, Data = "Hi There"
    let key1 = recover val
      let a = Array[U8].create(20)
      var i: USize = 0
      while i < 20 do a.push(0x0b); i = i + 1 end
      a
    end
    h.assert_eq[String](
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
      ToHexString(HmacSha256(key1, "Hi There")))

    // Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?"
    h.assert_eq[String](
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
      ToHexString(HmacSha256("Jefe", "what do ya want for nothing?")))

    // Test Case 3: Key = 20 bytes of 0xaa, Data = 50 bytes of 0xdd
    let key3 = recover val
      let a = Array[U8].create(20)
      var i: USize = 0
      while i < 20 do a.push(0xaa); i = i + 1 end
      a
    end
    let data3 = recover val
      let a = Array[U8].create(50)
      var i: USize = 0
      while i < 50 do a.push(0xdd); i = i + 1 end
      a
    end
    h.assert_eq[String](
      "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
      ToHexString(HmacSha256(key3, data3)))

    // Test Case 4: Key = 0x01..0x19, Data = 50 bytes of 0xcd
    let key4 = recover val
      let a = Array[U8].create(25)
      var i: U8 = 0x01
      while i <= 0x19 do a.push(i); i = i + 1 end
      a
    end
    let data4 = recover val
      let a = Array[U8].create(50)
      var i: USize = 0
      while i < 50 do a.push(0xcd); i = i + 1 end
      a
    end
    h.assert_eq[String](
      "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
      ToHexString(HmacSha256(key4, data4)))

    // Test Case 5: Truncation to 128 bits
    let key5 = recover val
      let a = Array[U8].create(20)
      var i: USize = 0
      while i < 20 do a.push(0x0c); i = i + 1 end
      a
    end
    let hmac5 = HmacSha256(key5, "Test With Truncation")
    h.assert_eq[String](
      "a3b6167473100ee06e0c796c2955552b",
      ToHexString(recover val
        let a = Array[U8].create(16)
        var i: USize = 0
        while i < 16 do
          try a.push(hmac5(i)?) end
          i = i + 1
        end
        a
      end))

    // Test Case 6: Key = 131 bytes of 0xaa, large key
    let key6 = recover val
      let a = Array[U8].create(131)
      var i: USize = 0
      while i < 131 do a.push(0xaa); i = i + 1 end
      a
    end
    h.assert_eq[String](
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
      ToHexString(HmacSha256(key6,
        "Test Using Larger Than Block-Size Key - Hash Key First")))

    // Test Case 7: Key = 131 bytes of 0xaa, large key + large data
    h.assert_eq[String](
      "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
      ToHexString(HmacSha256(key6,
        "This is a test using a larger than block-size key and a larger " +
        "than block-size data. The key needs to be hashed before being " +
        "used by the HMAC algorithm.")))

class \nodoc\ iso _TestHmacSha256Scram is UnitTest
  """
  HMAC-SHA-256 with SCRAM-SHA-256 intermediate values derived from the
  RFC 7677 protocol exchange. Verified against the RFC's ClientProof and
  ServerSignature.
  """
  fun name(): String => "crypto/HmacSha256/SCRAM"

  fun apply(h: TestHelper) =>
    // SaltedPassword from PBKDF2("pencil", salt, 4096, 32)
    let salted_password = recover val [as U8:
      0xc4; 0xa4; 0x95; 0x10; 0x32; 0x3a; 0xb4; 0xf9
      0x52; 0xca; 0xc1; 0xfa; 0x99; 0x44; 0x19; 0x39
      0xe7; 0x8e; 0xa7; 0x4d; 0x6b; 0xe8; 0x1d; 0xdf
      0x70; 0x96; 0xe8; 0x75; 0x13; 0xdc; 0x61; 0x5d
    ] end

    // HMAC(SaltedPassword, "Client Key")
    h.assert_eq[String](
      "a60fc923d67e8644a92d16b96eda5ef4656b0c725c484374be25535576996e8b",
      ToHexString(HmacSha256(salted_password, "Client Key")))

    // HMAC(SaltedPassword, "Server Key")
    h.assert_eq[String](
      "c1f3cbc1c13a9d35a14c0990eed97629ea225863e566a4314ab99f3f00e5d9d5",
      ToHexString(HmacSha256(salted_password, "Server Key")))

class \nodoc\ iso _TestPbkdf2Sha256Rfc7914 is UnitTest
  """
  PBKDF2-HMAC-SHA256 test vectors from RFC 7914, Section 11.
  """
  fun name(): String => "crypto/Pbkdf2Sha256/RFC7914"

  fun apply(h: TestHelper) ? =>
    ifdef "openssl_1.1.x" or "openssl_3.0.x" or "libressl" then
      // Test Vector 1: Password "passwd", Salt "salt", c=1, dkLen=64
      h.assert_eq[String](
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
        "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
        ToHexString(Pbkdf2Sha256("passwd", "salt", 1, 64)?))

      // Test Vector 2: Password "Password", Salt "NaCl", c=80000, dkLen=64
      h.assert_eq[String](
        "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56" +
        "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
        ToHexString(Pbkdf2Sha256("Password", "NaCl", 80000, 64)?))
    end

class \nodoc\ iso _TestPbkdf2Sha256Scram is UnitTest
  """
  PBKDF2-HMAC-SHA256 with the SCRAM-SHA-256 test vector from RFC 7677.
  The SaltedPassword is derived from the RFC 7677 protocol exchange and
  verified against the RFC's ClientProof and ServerSignature.
  """
  fun name(): String => "crypto/Pbkdf2Sha256/SCRAM"

  fun apply(h: TestHelper) ? =>
    ifdef "openssl_1.1.x" or "openssl_3.0.x" or "libressl" then
      // Salt: decoded bytes of base64 "W22ZaJ0SNY7soEsUEjb6gQ=="
      let salt = recover val [as U8:
        0x5b; 0x6d; 0x99; 0x68; 0x9d; 0x12; 0x35; 0x8e
        0xec; 0xa0; 0x4b; 0x14; 0x12; 0x36; 0xfa; 0x81
      ] end

      h.assert_eq[String](
        "c4a49510323ab4f952cac1fa99441939e78ea74d6be81ddf7096e87513dc615d",
        ToHexString(Pbkdf2Sha256("pencil", salt, 4096, 32)?))
    end

class \nodoc\ iso _TestRandBytes is UnitTest
  fun name(): String => "crypto/RandBytes"

  fun apply(h: TestHelper) ? =>
    // Zero-length request
    let r0 = RandBytes(0)?
    h.assert_eq[USize](0, r0.size())

    // Single byte
    let r1 = RandBytes(1)?
    h.assert_eq[USize](1, r1.size())

    // 32 bytes
    let r32 = RandBytes(32)?
    h.assert_eq[USize](32, r32.size())

// PonyCheck property tests

class \nodoc\ iso _TestHmacSha256OutputLength is Property1[USize]
  fun name(): String => "crypto/HmacSha256/property/output_length"

  fun gen(): Generator[USize] =>
    Generators.usize(0, 256)

  fun ref property(sample: USize, h: PropertyHelper) =>
    let key = recover val Array[U8].init(0x42, sample) end
    let data = recover val Array[U8].init(0xAB, sample) end
    h.assert_eq[USize](32, HmacSha256(key, data).size())

class \nodoc\ iso _TestHmacSha256Deterministic is Property1[USize]
  fun name(): String => "crypto/HmacSha256/property/deterministic"

  fun gen(): Generator[USize] =>
    Generators.usize(0, 256)

  fun ref property(sample: USize, h: PropertyHelper) =>
    let key = recover val Array[U8].init(0x42, sample) end
    let data = recover val Array[U8].init(0xAB, sample) end
    h.assert_array_eq[U8](HmacSha256(key, data), HmacSha256(key, data))

class \nodoc\ iso _TestPbkdf2Sha256OutputLength is Property1[USize]
  fun name(): String => "crypto/Pbkdf2Sha256/property/output_length"

  fun gen(): Generator[USize] =>
    Generators.usize(1, 128)

  fun ref property(sample: USize, h: PropertyHelper) ? =>
    ifdef "openssl_1.1.x" or "openssl_3.0.x" or "libressl" then
      h.assert_eq[USize](sample,
        Pbkdf2Sha256("p", "s", 1, sample)?.size())
    end

class \nodoc\ iso _TestPbkdf2Sha256Deterministic is Property1[USize]
  fun name(): String => "crypto/Pbkdf2Sha256/property/deterministic"

  fun gen(): Generator[USize] =>
    Generators.usize(1, 64)

  fun ref property(sample: USize, h: PropertyHelper) ? =>
    ifdef "openssl_1.1.x" or "openssl_3.0.x" or "libressl" then
      h.assert_array_eq[U8](
        Pbkdf2Sha256("p", "s", 1, sample)?,
        Pbkdf2Sha256("p", "s", 1, sample)?)
    end

class \nodoc\ iso _TestRandBytesOutputLength is Property1[USize]
  fun name(): String => "crypto/RandBytes/property/output_length"

  fun gen(): Generator[USize] =>
    Generators.usize(0, 256)

  fun ref property(sample: USize, h: PropertyHelper) ? =>
    h.assert_eq[USize](sample, RandBytes(sample)?.size())

class \nodoc\ iso _TestRandBytesNonConstant is Property1[USize]
  fun name(): String => "crypto/RandBytes/property/non_constant"

  fun gen(): Generator[USize] =>
    Generators.usize(16, 256)

  fun ref property(sample: USize, h: PropertyHelper) ? =>
    let a = RandBytes(sample)?
    let b = RandBytes(sample)?
    h.assert_false(ConstantTimeCompare(a, b))

class \nodoc\ iso _TestShake128OutputLength is Property1[USize]
  fun name(): String => "crypto/Shake128/property/output_length"

  fun gen(): Generator[USize] =>
    Generators.usize(1, 256)

  fun ref property(sample: USize, h: PropertyHelper) ? =>
    ifdef "openssl_3.0.x" then
      let d = Digest.shake128(sample)
      d.append("test")?
      h.assert_eq[USize](sample, d.final().size())
    end

class \nodoc\ iso _TestShake256OutputLength is Property1[USize]
  fun name(): String => "crypto/Shake256/property/output_length"

  fun gen(): Generator[USize] =>
    Generators.usize(1, 256)

  fun ref property(sample: USize, h: PropertyHelper) ? =>
    ifdef "openssl_3.0.x" then
      let d = Digest.shake256(sample)
      d.append("test")?
      h.assert_eq[USize](sample, d.final().size())
    end

class \nodoc\ iso _TestShake128XofPrefix is Property1[USize]
  fun name(): String => "crypto/Shake128/property/xof_prefix"

  fun gen(): Generator[USize] =>
    Generators.usize(2, 256)

  fun ref property(sample: USize, h: PropertyHelper) ? =>
    ifdef "openssl_3.0.x" then
      let small_size = sample / 2
      let large_size = sample

      let small = Digest.shake128(small_size)
      small.append("test input")?
      let small_result = small.final()

      let large = Digest.shake128(large_size)
      large.append("test input")?
      let large_result = large.final()

      h.assert_array_eq[U8](small_result,
        large_result.trim(0, small_size))
    end

class \nodoc\ iso _TestShake256XofPrefix is Property1[USize]
  fun name(): String => "crypto/Shake256/property/xof_prefix"

  fun gen(): Generator[USize] =>
    Generators.usize(2, 256)

  fun ref property(sample: USize, h: PropertyHelper) ? =>
    ifdef "openssl_3.0.x" then
      let small_size = sample / 2
      let large_size = sample

      let small = Digest.shake256(small_size)
      small.append("test input")?
      let small_result = small.final()

      let large = Digest.shake256(large_size)
      large.append("test input")?
      let large_result = large.final()

      h.assert_array_eq[U8](small_result,
        large_result.trim(0, small_size))
    end
