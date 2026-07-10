"""
The crypto package provides cryptographic primitives built on OpenSSL:

* One-shot hash functions (`MD5`, `SHA256`, etc.) and streaming digests
  (`Digest`)
* HMAC message authentication (`HmacSha256`)
* PBKDF2 key derivation (`Pbkdf2Sha256`)
* Cryptographically secure random bytes (`RandBytes`)
* Constant-time comparison (`ConstantTimeCompare`)

## When a call can fail

A call here gives back a correct result or it raises. It never gives back an
incorrect one, so there is no value to check for and no sentinel to compare
against.

`Digest.append`, `Digest.final`, `HmacSha256`, `Pbkdf2Sha256` and `RandBytes`
are partial. They raise when OpenSSL could not do what was asked of it.
`HmacSha256`, `Pbkdf2Sha256` and `RandBytes` also raise when a length you gave
them is larger than the C `int` OpenSSL takes for it. Constructing a `Digest`
cannot fail; a context OpenSSL would not give you surfaces at the first
`append` or `final`.

The one-shot hash functions and `ConstantTimeCompare` cannot fail and are total.

When `HmacSha256` raises, reject the message. Do not compare it against a code
of your own making — a code you invent is one an attacker can send you.
"""

use @pony_ctx[Pointer[None]]()
use @pony_alloc[Pointer[U8]](ctx: Pointer[None], size: USize)
