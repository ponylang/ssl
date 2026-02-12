## Add first-class LibreSSL support

LibreSSL users previously had to build with `-Dopenssl_0.9.0`, which forced LibreSSL through a code path designed for ancient OpenSSL. This silently disabled ALPN negotiation, PBKDF2 key derivation, and the modern EVP/init APIs that LibreSSL supports.

LibreSSL now has its own define. Projects that build against LibreSSL should switch from `-Dopenssl_0.9.0` to `-Dlibressl`.

