## Add OpenSSL 4.0.x support

OpenSSL 4.0.x is now a supported backend. Select it at compile time with `-Dopenssl_4.0.x`, or pass `ssl=4.0.x` to `make` when building the library itself. The library's API is unchanged; existing code continues to work without modification.

