use "path:/usr/local/opt/libressl/lib" if osx and x86
use "path:/opt/homebrew/opt/libressl/lib" if osx and arm
use "lib:crypto"
use "lib:bcrypt" if windows

use @EVP_MD_CTX_new[Pointer[_EVPCTX]]() if "openssl_1.1.x" or "openssl_3.0.x" or "openssl_4.0.x" or "libressl"
use @EVP_DigestInit_ex[I32](ctx: Pointer[_EVPCTX] tag, t: Pointer[_EVPMD], impl: Pointer[None])
use @EVP_DigestUpdate[I32](ctx: Pointer[_EVPCTX] tag, d: Pointer[U8] tag, cnt: USize)
use @EVP_DigestFinal_ex[I32](ctx: Pointer[_EVPCTX] tag, md: Pointer[U8] tag, s: Pointer[U32])
use @EVP_DigestFinalXOF[I32](ctx: Pointer[_EVPCTX] tag, md: Pointer[U8] tag, len: USize) if "openssl_3.0.x" or "openssl_4.0.x"
use @EVP_MD_CTX_free[None](ctx: Pointer[_EVPCTX] tag) if "openssl_1.1.x" or "openssl_3.0.x" or "openssl_4.0.x" or "libressl"

use @EVP_md5[Pointer[_EVPMD]]()
use @EVP_ripemd160[Pointer[_EVPMD]]()
use @EVP_sha1[Pointer[_EVPMD]]()
use @EVP_sha224[Pointer[_EVPMD]]()
use @EVP_sha256[Pointer[_EVPMD]]()
use @EVP_sha384[Pointer[_EVPMD]]()
use @EVP_sha512[Pointer[_EVPMD]]()
use @EVP_shake128[Pointer[_EVPMD]]()
use @EVP_shake256[Pointer[_EVPMD]]()

primitive _EVPMD
primitive _EVPCTX

primitive _EVPContext
  fun apply(md: Pointer[_EVPMD]): Pointer[_EVPCTX] ? =>
    """
    A context initialised for `md`. Raises when OpenSSL could not give us one.

    This is the only place a `Digest` allocates a context, so a `_ctx` is an
    initialised and usable one everywhere else.
    """
    ifdef "openssl_1.1.x" or "openssl_3.0.x" or "openssl_4.0.x" or "libressl" then
      let ctx = @EVP_MD_CTX_new()
      if ctx.is_null() then error end

      if @EVP_DigestInit_ex(ctx, md, Pointer[None]) != 1 then
        @EVP_MD_CTX_free(ctx)
        error
      end

      ctx
    else
      compile_error "You must select an SSL version to use."
    end

class Digest
  """
  Produces a hash from the chunks of input. Feed the input with append() and
  produce a final hash from the concatenation of the input with final().

  A digest gives back the hash of its input, or it raises. It never gives back
  a hash of something else. Constructing one raises when OpenSSL cannot give it
  a context; `append()` and `final()` raise when OpenSSL could not do what was
  asked of them.
  """
  let _digest_size: USize
  var _ctx: Pointer[_EVPCTX] = Pointer[_EVPCTX]
  let _variable_length: Bool
  var _hash: (Array[U8] val | None) = None

  new md5() ? =>
    """
    Use the MD5 algorithm to calculate the hash.
    """
    _variable_length = false
    _digest_size = 16
    _ctx = _EVPContext(@EVP_md5())?

  new ripemd160() ? =>
    """
    Use the RIPEMD160 algorithm to calculate the hash.
    """
    _variable_length = false
    _digest_size = 20
    _ctx = _EVPContext(@EVP_ripemd160())?

  new sha1() ? =>
    """
    Use the SHA1 algorithm to calculate the hash.
    """
    _variable_length = false
    _digest_size = 20
    _ctx = _EVPContext(@EVP_sha1())?

  new sha224() ? =>
    """
    Use the SHA224 algorithm to calculate the hash.
    """
    _variable_length = false
    _digest_size = 28
    _ctx = _EVPContext(@EVP_sha224())?

  new sha256() ? =>
    """
    Use the SHA256 algorithm to calculate the hash.
    """
    _variable_length = false
    _digest_size = 32
    _ctx = _EVPContext(@EVP_sha256())?

  new sha384() ? =>
    """
    Use the SHA384 algorithm to calculate the hash.
    """
    _variable_length = false
    _digest_size = 48
    _ctx = _EVPContext(@EVP_sha384())?

  new sha512() ? =>
    """
    Use the SHA512 algorithm to calculate the hash.
    """
    _variable_length = false
    _digest_size = 64
    _ctx = _EVPContext(@EVP_sha512())?

  new shake128(size': USize = 16) ? =>
    """
    Use the SHAKE128 algorithm to calculate the hash.

    SHAKE128 is an extendable output function (XOF) that can produce
    variable-length output. The `size'` parameter controls the output length
    in bytes (default: 16). Variable-length output requires OpenSSL 3.0.x or
    OpenSSL 4.0.x; on OpenSSL 1.1.x, the default size is always used.
    """
    ifdef "openssl_1.1.x" or "openssl_3.0.x" or "openssl_4.0.x" then
      ifdef "openssl_3.0.x" or "openssl_4.0.x" then
        _variable_length = true
        _digest_size = size'
      else
        _variable_length = false
        _digest_size = 16
      end
      _ctx = _EVPContext(@EVP_shake128())?
    else
      compile_error "shake128 is only supported with OpenSSL 1.1.x, 3.0.x, or 4.0.x"
    end

  new shake256(size': USize = 32) ? =>
    """
    Use the SHAKE256 algorithm to calculate the hash.

    SHAKE256 is an extendable output function (XOF) that can produce
    variable-length output. The `size'` parameter controls the output length
    in bytes (default: 32). Variable-length output requires OpenSSL 3.0.x or
    OpenSSL 4.0.x; on OpenSSL 1.1.x, the default size is always used.
    """
    ifdef "openssl_1.1.x" or "openssl_3.0.x" or "openssl_4.0.x" then
      ifdef "openssl_3.0.x" or "openssl_4.0.x" then
        _variable_length = true
        _digest_size = size'
      else
        _variable_length = false
        _digest_size = 32
      end
      _ctx = _EVPContext(@EVP_shake256())?
    else
      compile_error "shake256 is only supported with OpenSSL 1.1.x, 3.0.x, or 4.0.x"
    end

  fun ref append(input: ByteSeq) ? =>
    """
    Update the digest with input.

    Raises an error when `final()` has already been called, and when OpenSSL
    could not take the input.
    """
    if _ctx.is_null() then error end
    if @EVP_DigestUpdate(_ctx, input.cpointer(), input.size()) != 1 then
      error
    end

  fun ref final(): Array[U8] val ? =>
    """
    Return the digest of the strings passed to the append() method. A second
    call returns the hash the first one made.

    Raises an error when OpenSSL could not produce the hash. A digest that
    raises here has no hash to give, and raises from every later call.
    """
    match _hash
    | let h: Array[U8] val => h
    else
      if _ctx.is_null() then error end

      let size = _digest_size
      let digest =
        recover String.from_cpointer(
          @pony_alloc(@pony_ctx(), size), size)
        end

      var rc: I32 = 0
      ifdef "openssl_3.0.x" or "openssl_4.0.x" then
        rc =
          if _variable_length then
            @EVP_DigestFinalXOF(_ctx, digest.cpointer(), size)
          else
            @EVP_DigestFinal_ex(_ctx, digest.cpointer(), Pointer[U32])
          end
      elseif "openssl_1.1.x" or "libressl" then
        rc = @EVP_DigestFinal_ex(_ctx, digest.cpointer(), Pointer[U32])
      else
        compile_error "You must select an SSL version to use."
      end

      ifdef "openssl_1.1.x" or "openssl_3.0.x" or "openssl_4.0.x" or "libressl" then
        @EVP_MD_CTX_free(_ctx)
      else
        compile_error "You must select an SSL version to use."
      end
      _ctx = Pointer[_EVPCTX]

      // `@pony_alloc` does not zero the memory it returns, so a digest OpenSSL
      // did not write holds whatever this actor freed last. Raising drops it
      // rather than handing it back as a hash.
      if rc != 1 then error end

      let h = (consume digest).array()
      _hash = h
      h
    end

  fun _final() =>
    """
    Free the context of a digest that was dropped without a call to `final()`.
    """
    if not _ctx.is_null() then
      ifdef "openssl_1.1.x" or "openssl_3.0.x" or "openssl_4.0.x" or "libressl" then
        @EVP_MD_CTX_free(_ctx)
      else
        compile_error "You must select an SSL version to use."
      end
    end

  fun digest_size(): USize =>
    """
    Return the size of the message digest in bytes.
    """
    _digest_size
