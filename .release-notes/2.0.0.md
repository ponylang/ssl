## Add first-class LibreSSL support

LibreSSL users previously had to build with `-Dopenssl_0.9.0`, which forced LibreSSL through a code path designed for ancient OpenSSL. This silently disabled ALPN negotiation, PBKDF2 key derivation, and the modern EVP/init APIs that LibreSSL supports.

LibreSSL now has its own define. Projects that build against LibreSSL should switch from `-Dopenssl_0.9.0` to `-Dlibressl`.

## SSLConnection ignores _notify.received value

Previously, when a `TCPConnectionNotify` wrapped by `SSLConnection` returned `false` from its `received` callback to request yielding to other actors, `SSLConnection` discarded the return value and always told `TCPConnection` to continue reading. This meant backpressure signaling through SSL connections had no effect.

`SSLConnection` now properly propagates the wrapped notify's `received` return value to `TCPConnection`, allowing the backpressure/yield mechanism to work through SSL connections.

## Add variable-length output support to SHAKE digests

The `shake128` and `shake256` constructors on `Digest` now accept an optional `size` parameter that controls the output length in bytes. The defaults match the previous fixed sizes (16 bytes for SHAKE128, 32 for SHAKE256), so existing code is unaffected.

Variable-length output requires OpenSSL 3.0.x. On OpenSSL 1.1.x, the default size is always used regardless of the parameter value.

```pony
// 64-byte SHAKE256 digest (OpenSSL 3.0.x)
let d = Digest.shake256(64)
d.append("input data")?
let hash: Array[U8] val = d.final()  // 64 bytes
```

