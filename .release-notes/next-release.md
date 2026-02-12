## Add first-class LibreSSL support

LibreSSL users previously had to build with `-Dopenssl_0.9.0`, which forced LibreSSL through a code path designed for ancient OpenSSL. This silently disabled ALPN negotiation, PBKDF2 key derivation, and the modern EVP/init APIs that LibreSSL supports.

LibreSSL now has its own define. Projects that build against LibreSSL should switch from `-Dopenssl_0.9.0` to `-Dlibressl`.

## SSLConnection ignores _notify.received value

Previously, when a `TCPConnectionNotify` wrapped by `SSLConnection` returned `false` from its `received` callback to request yielding to other actors, `SSLConnection` discarded the return value and always told `TCPConnection` to continue reading. This meant backpressure signaling through SSL connections had no effect.

`SSLConnection` now properly propagates the wrapped notify's `received` return value to `TCPConnection`, allowing the backpressure/yield mechanism to work through SSL connections.

