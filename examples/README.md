# Examples

Each subdirectory is a self-contained Pony program demonstrating a
different part of the ssl library. Ordered from simplest to most
involved: the hashing examples come first, the SSL networking example
follows.

## [hash-fn-example](hash-fn-example/)

Computes MD5, SHA1, and SHA256 hashes of a string in a single call each
and prints the results. Shows the one-shot convenience functions `MD5`,
`SHA1`, and `SHA256` from `ssl/crypto`, plus `ToHexString` for
formatting the resulting `Array[U8] val`. Start here if you're new to
the library.

## [digest-example](digest-example/)

Hashes data in chunks using the streaming `Digest` API. Creates a
`Digest.sha256()`, appends two string pieces with `append()`, and
finalizes with `final()` to produce the hash. Also demonstrates
`Digest.shake256(n)` for variable-length output on OpenSSL 3.0.x and
4.0.x, guarded by an `ifdef`.

## [ssl-client-server-example](ssl-client-server-example/)

Runs a TLS client and server in the same process, exchanging a few
messages over a loopback TCP connection. Demonstrates setting up an
`SSLContext` with `set_authority`, `set_cert`, and verification toggled
off, then wrapping both sides of a `TCPConnection` with `SSLConnection`
from `ssl/net`. Requires an `assets/cert.pem` and `assets/key.pem`
alongside the example — see the source comments for how the relative
paths are resolved.
