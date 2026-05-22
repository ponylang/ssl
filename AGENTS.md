# SSL Package

Pony bindings for OpenSSL and LibreSSL, providing SSL networking (`ssl/net`) and cryptographic primitives (`ssl/crypto`).

<!-- contributor-only -->
## Contributing with an AI assistant

This is a Pony project. The ponylang org maintains a set of LLM coding skills. Get set up with them before contributing:

- **Not set up yet?** Install them once:

  ```bash
  git clone https://github.com/ponylang/llm-skills.git
  cd llm-skills
  python install.py
  ```

- **Already set up?** Make sure you're on the latest. If you installed with the script above, `git pull` in the directory where you cloned `llm-skills` and the symlinked skills update automatically — if you set them up another way, refresh them however that setup expects.

See the [llm-skills README](https://github.com/ponylang/llm-skills) for details and other harnesses.

When you start working on this project, load the `pony-skills` skill — it tells your assistant which Pony skill to use for each task.

Read [CONTRIBUTING.md](CONTRIBUTING.md).
<!-- /contributor-only -->

## Building and Testing

Always use `make` rather than running `ponyc` directly. The Makefile uses `corral` to fetch dependencies before compiling.

```
make test config=debug ssl=<version>
make test-one t=TestName ssl=3.0.x  # run a single test by name
```

SSL version is **required**. Valid values:

| `ssl=` value | Define passed to ponyc | Backend |
|---|---|---|
| `4.0.x` | `-Dopenssl_4.0.x` | OpenSSL 4.x |
| `3.0.x` | `-Dopenssl_3.0.x` | OpenSSL 3.x |
| `1.1.x` | `-Dopenssl_1.1.x` | OpenSSL 1.1.x |
| `libressl` | `-Dlibressl` | LibreSSL |

Windows (`make.ps1`) always uses LibreSSL. The define is hardcoded. Prebuilt LibreSSL binaries are downloaded by `.ci-scripts/windows-install-libressl.ps1` rather than built from source.

### LibreSSL API Divergences from OpenSSL 1.1.x

LibreSSL's API is mostly OpenSSL 1.1.x compatible, with five differences that require separate code paths:

1. **`sk_pop`/`sk_free`** — LibreSSL uses old names (no `OPENSSL_` prefix)
2. **`SSL_CTX_set_options`/`SSL_CTX_clear_options`** — macros in LibreSSL, not real functions. Pony FFI can't call macros, so LibreSSL uses `SSL_CTX_ctrl`
3. **`SSL_has_pending`** — not available in LibreSSL; only `SSL_pending` exists
4. **`SSL_get_peer_certificate`** — LibreSSL uses the pre-3.0.x name (not `SSL_get1_peer_certificate`)
5. **`OPENSSL_INIT_new`/`OPENSSL_INIT_free`** — not available in LibreSSL. Init uses `OPENSSL_init_ssl` directly with no settings object

## ifdef Conventions

Version-specific code uses two patterns:

**FFI declarations** use `if` guards on the `use` statement:
```pony
use @TLS_method[Pointer[None]]() if "openssl_1.1.x" or "openssl_3.0.x" or "openssl_4.0.x" or "libressl"
```

**Code blocks** use `ifdef` with `elseif` chains and a compile_error catch-all:
```pony
ifdef "openssl_1.1.x" or "openssl_3.0.x" or "openssl_4.0.x" then
  // OpenSSL path
elseif "libressl" then
  // LibreSSL path (when it diverges from OpenSSL)
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
