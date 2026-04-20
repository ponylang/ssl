"""
The crypto package provides cryptographic primitives built on OpenSSL:

* One-shot hash functions (`MD5`, `SHA256`, etc.) and streaming digests
  (`Digest`)
* HMAC message authentication (`HmacSha256`)
* PBKDF2 key derivation (`Pbkdf2Sha256`)
* Cryptographically secure random bytes (`RandBytes`)
* Constant-time comparison (`ConstantTimeCompare`)
"""

use @pony_ctx[Pointer[None]]()
use @pony_alloc[Pointer[U8]](ctx: Pointer[None], size: USize)
