## Use prebuilt LibreSSL binaries on Windows

The `libs` command has been removed from `make.ps1`. CI now downloads prebuilt LibreSSL static libraries directly from the [LibreSSL GitHub releases](https://github.com/libressl/portable/releases) instead of building from source. Windows users who were using `make.ps1 -Command libs` to build LibreSSL locally can download prebuilt binaries from the same location. Prebuilt binaries are available for x86-64 and ARM64.

## Add OpenSSL 4.0.x support

OpenSSL 4.0.x is now a supported backend. Select it at compile time with `-Dopenssl_4.0.x`, or pass `ssl=4.0.x` to `make` when building the library itself. The library's API is unchanged; existing code continues to work without modification.

