# SSL Package

Pony bindings for OpenSSL and LibreSSL, providing SSL networking (`ssl/net`) and cryptographic primitives (`ssl/crypto`).

## Building and Testing

Always use `make` rather than running `ponyc` directly. The Makefile uses `corral` to fetch dependencies before compiling.

```
make test config=debug ssl=<version>
```

SSL version is **required**. Valid values:

| `ssl=` value | Define passed to ponyc | Backend |
|---|---|---|
| `3.0.x` | `-Dopenssl_3.0.x` | OpenSSL 3.x |
| `1.1.x` | `-Dopenssl_1.1.x` | OpenSSL 1.1.x |
| `0.9.0` | `-Dopenssl_0.9.0` | Legacy (pending removal via #9 PR 2) |
| `libressl` | `-Dlibressl` | LibreSSL |

Windows (`make.ps1`) always builds against LibreSSL. The define is hardcoded on line 70.

### LibreSSL API Divergences from OpenSSL 1.1.x

LibreSSL's API is mostly OpenSSL 1.1.x compatible, with five differences that require separate code paths:

1. **`sk_pop`/`sk_free`** — LibreSSL uses old names (no `OPENSSL_` prefix)
2. **`SSL_CTX_set_options`/`SSL_CTX_clear_options`** — macros in LibreSSL, not real functions. Pony FFI can't call macros, so LibreSSL uses `SSL_CTX_ctrl` (same as the 0.9.0 approach)
3. **`SSL_has_pending`** — not available in LibreSSL; only `SSL_pending` exists
4. **`SSL_get_peer_certificate`** — LibreSSL uses the pre-3.0.x name (not `SSL_get1_peer_certificate`)
5. **`OPENSSL_INIT_new`/`OPENSSL_INIT_free`** — not available in LibreSSL. Init uses `OPENSSL_init_ssl` directly with no settings object

## ifdef Conventions

Version-specific code uses two patterns:

**FFI declarations** use `if` guards on the `use` statement:
```pony
use @TLS_method[Pointer[None]]() if "openssl_1.1.x" or "openssl_3.0.x" or "libressl"
use @SSLv23_method[Pointer[None]]() if "openssl_0.9.0"
```

**Code blocks** use `ifdef` with `elseif` chains and a compile_error catch-all:
```pony
ifdef "openssl_1.1.x" or "openssl_3.0.x" then
  // modern path
elseif "openssl_0.9.0" then
  // legacy path
else
  compile_error "You must select an SSL version to use."
end
```

Every ifdef chain must end with `compile_error` to catch missing defines at compile time.

## Key Files

| File | Role |
|---|---|
| `ssl/net/_ssl_init.pony` | SSL library initialization (threading model differs by version) |
| `ssl/net/ssl_context.pony` | Context management, ALPN setup, TLS version control |
| `ssl/net/ssl.pony` | SSL session — handshake, read/write, certificate verification |
| `ssl/net/x509.pony` | Certificate name extraction and hostname matching |
| `ssl/crypto/digest.pony` | Hash digests (MD5, SHA family, SHAKE) via EVP API |
| `ssl/crypto/hmac_sha256.pony` | HMAC-SHA-256 message authentication (RFC 2104) |
| `ssl/crypto/pbkdf2_sha256.pony` | PBKDF2 key derivation with HMAC-SHA-256 (RFC 2898, OpenSSL 1.1.x+/LibreSSL) |
| `ssl/crypto/rand_bytes.pony` | Cryptographically secure random byte generation |

## Known Issues

- `digest.pony` lines 7 and 13 have an operator precedence bug: `if not "openssl_1.1.x" or "openssl_3.0.x"` parses as `(not "openssl_1.1.x") or "openssl_3.0.x"` rather than the intended `not ("openssl_1.1.x" or "openssl_3.0.x")`. Harmless in practice since the declarations are unused when the wrong version is active. Will be resolved when the 0.9.0 path is removed (#9 PR 2).
