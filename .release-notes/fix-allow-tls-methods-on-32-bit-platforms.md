## Fix allow_tls_v1, allow_tls_v1_1 and allow_tls_v1_2 on 32-bit platforms

`SSLContext.allow_tls_v1`, `SSLContext.allow_tls_v1_1` and `SSLContext.allow_tls_v1_2` did not change the protocol version they name, and left the context with TLS options nobody asked for. A call meant to forbid a version left it allowed, a call meant to allow one left it forbidden, and unrelated TLS features were switched on either way.

This affected 32-bit builds using OpenSSL 3.x or 4.x. 64-bit builds, LibreSSL builds, and OpenSSL 1.1.x builds were never affected.

These methods now change only the protocol version they name.
