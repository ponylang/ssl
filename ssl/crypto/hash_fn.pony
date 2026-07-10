use "path:/usr/local/opt/libressl/lib" if osx and x86
use "path:/opt/homebrew/opt/libressl/lib" if osx and arm
use "lib:crypto"

use @MD4[Pointer[U8]](d: Pointer[U8] tag, n: USize, md: Pointer[U8])
use @MD5[Pointer[U8]](d: Pointer[U8] tag, n: USize, md: Pointer[U8])
use @RIPEMD160[Pointer[U8]](d: Pointer[U8] tag, n: USize, md: Pointer[U8])
use @SHA1[Pointer[U8]](d: Pointer[U8] tag, n: USize, md: Pointer[U8])
use @SHA224[Pointer[U8]](d: Pointer[U8] tag, n: USize, md: Pointer[U8])
use @SHA256[Pointer[U8]](d: Pointer[U8] tag, n: USize, md: Pointer[U8])
use @SHA384[Pointer[U8]](d: Pointer[U8] tag, n: USize, md: Pointer[U8])
use @SHA512[Pointer[U8]](d: Pointer[U8] tag, n: USize, md: Pointer[U8])

use "format"

interface HashFn
  """
  Produces a fixed-length byte array based on the input sequence.
  """
  fun apply(input: ByteSeq): Array[U8] val
    """
    The digest of `input`. The same input always gives the same digest, and
    every digest an implementation gives back has the same length.
    """

primitive MD4 is HashFn
  """
  Compute the MD4 message digest conforming to RFC 1320. Returns 16 bytes.
  """
  fun apply(input: ByteSeq): Array[U8] val =>
    recover
      let size: USize = 16
      let digest = @pony_alloc(@pony_ctx(), size)
      @MD4(input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive MD5 is HashFn
  """
  Compute the MD5 message digest conforming to RFC 1321. Returns 16 bytes.
  """
  fun apply(input: ByteSeq): Array[U8] val =>
    recover
      let size: USize = 16
      let digest = @pony_alloc(@pony_ctx(), size)
      @MD5(input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive RIPEMD160 is HashFn
  """
  Compute the RIPEMD160 message digest conforming to ISO/IEC 10118-3. Returns
  20 bytes.
  """
  fun apply(input: ByteSeq): Array[U8] val =>
    recover
      let size: USize = 20
      let digest = @pony_alloc(@pony_ctx(), size)
      @RIPEMD160(input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive SHA1 is HashFn
  """
  Compute the SHA1 message digest conforming to US Federal Information
  Processing Standard FIPS PUB 180-4. Returns 20 bytes.
  """
  fun apply(input: ByteSeq): Array[U8] val =>
    recover
      let size: USize = 20
      let digest = @pony_alloc(@pony_ctx(), size)
      @SHA1(input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive SHA224 is HashFn
  """
  Compute the SHA224 message digest conforming to US Federal Information
  Processing Standard FIPS PUB 180-4. Returns 28 bytes.
  """
  fun apply(input: ByteSeq): Array[U8] val =>
    recover
      let size: USize = 28
      let digest = @pony_alloc(@pony_ctx(), size)
      @SHA224(input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive SHA256 is HashFn
  """
  Compute the SHA256 message digest conforming to US Federal Information
  Processing Standard FIPS PUB 180-4. Returns 32 bytes.
  """
  fun apply(input: ByteSeq): Array[U8] val =>
    recover
      let size: USize = 32
      let digest = @pony_alloc(@pony_ctx(), size)
      @SHA256(input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive SHA384 is HashFn
  """
  Compute the SHA384 message digest conforming to US Federal Information
  Processing Standard FIPS PUB 180-4. Returns 48 bytes.
  """
  fun apply(input: ByteSeq): Array[U8] val =>
    recover
      let size: USize = 48
      let digest = @pony_alloc(@pony_ctx(), size)
      @SHA384(input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive SHA512 is HashFn
  """
  Compute the SHA512 message digest conforming to US Federal Information
  Processing Standard FIPS PUB 180-4. Returns 64 bytes.
  """
  fun apply(input: ByteSeq): Array[U8] val =>
    recover
      let size: USize = 64
      let digest = @pony_alloc(@pony_ctx(), size)
      @SHA512(input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive ToHexString
  """
  Return the lower-case hexadecimal string representation of the given Array
  of U8.

  ```pony
  let hex = ToHexString(SHA256("Hello World"))
  ```
  """
  fun apply(bs: Array[U8] val): String =>
    let out = recover String(bs.size() * 2) end
    for c in bs.values() do
      out.append(Format.int[U8](c where
        fmt = FormatHexSmallBare, width = 2, fill = '0'))
    end
    consume out
