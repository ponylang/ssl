# Examples

Each subdirectory is a self-contained Pony program demonstrating a
different part of the ssl library. The hashing examples show the
cryptographic primitives from `ssl/crypto`.

## [hash-fn](hash-fn/)

Computes MD5, SHA1, and SHA256 hashes of a string in a single call each
and prints the results. Shows the one-shot convenience functions `MD5`,
`SHA1`, and `SHA256` from `ssl/crypto`, plus `ToHexString` for
formatting the resulting `Array[U8] val`. Start here if you're new to
the library.

## [digest](digest/)

Hashes data in chunks using the streaming `Digest` API. Creates a
`Digest.sha256()`, appends two string pieces with `append()`, and
finalizes with `final()` to produce the hash. Also demonstrates
`Digest.shake256(n)` for variable-length output on OpenSSL 3.0.x and
4.0.x, guarded by an `ifdef`.
