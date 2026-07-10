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
make lint                           # pony-lint the sources; no ssl= needed
```

`make lint` runs `pony-lint` over `ssl` and `examples`. It needs no `ssl=`,
because the linter is text-based and does not compile. CI runs it as its own
job. `examples/.pony-lint.json` turns off `style/package-docstring` there — an
example program has no package file to hang a docstring on.

SSL version is **required** for building and testing. Valid values:

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

## Dispose Conventions

`dispose()` frees the OpenSSL handle and nulls the pointer field, so any later call would hand OpenSSL a null. Most of the C functions dereference it without checking, and the ones that don't vary by backend — `SSL_CTX_ctrl` returns 0 for a null context on OpenSSL but dereferences it on LibreSSL. Check `is_null()` before calling into OpenSSL, and don't count on a backend being forgiving.

Pony registers a `_final` when it allocates the object, not when the constructor returns, so `_final` runs even on an object whose constructor raised. A pointer field that `_final` frees needs a null default at its declaration, or it frees whatever was left in the recycled heap slot.

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

**One symbol whose C signature changes by version** needs two `use` statements, and the second guard must exclude the first. ponyc resolves an FFI call by enumerating every combination of the defines named in the guards, not just the one the build passes, and nothing tells it the `ssl=` defines are mutually exclusive. Overlapping guards give "Multiple possible declarations for FFI call":
```pony
use @SSL_CTX_set_options[U64](ctx: Pointer[_SSLContext] tag, opts: U64) if "openssl_3.0.x" or "openssl_4.0.x"
use @SSL_CTX_set_options[ULong](ctx: Pointer[_SSLContext] tag, opts: ULong) if "openssl_1.1.x" and not ("openssl_3.0.x" or "openssl_4.0.x")
```
`libressl` appears in neither guard because LibreSSL reaches these options through `SSL_CTX_ctrl` instead — see LibreSSL API Divergences above.

The call site needs an `ifdef` split too. Pony has no implicit numeric conversion, so one call expression cannot satisfy both parameter types.

Adding a new SSL define means adding it to the exclusion list. Forgetting is safe: the enumeration finds the overlap and fails the build on every backend, not just the new one.

Every ifdef chain must end with `compile_error` to catch missing defines at compile time.

## FFI Type Conventions

Declare the Pony type that corresponds to the C type in the header, not one that happens to be the same width on the platforms CI builds:

| C type | Pony type |
|---|---|
| `int` / `unsigned int` | `I32` / `U32` |
| `long` / `unsigned long` | `ILong` / `ULong` |
| `size_t` | `USize` |
| `uint64_t` | `U64` |
| pointer to an opaque C struct | `Pointer[_Name]`, declaring a phantom primitive for it |
| `void *`, or a pointer only ever passed as null | `Pointer[None]` |
| pointer to bytes | `Pointer[U8]` |

`ILong`/`ULong` track C's `long`: 32 bits on Windows and on 32-bit targets such as `arm32`, 64 bits on 64-bit Unix-like targets. `USize` tracks `size_t`, which is pointer-width. Neither is a stand-in for `uint64_t`. Reaching for `ULong` because it is 64 bits on the platform in front of you turns a correct call into a wrong one everywhere else — `SSL_CTX_set_options` takes a `uint64_t` in OpenSSL 3.x, and a `ULong` declaration passes 32 bits on every 32-bit build.

A `Pointer[X]`'s element type never reaches the ABI, so `Pointer[USize]` where C says `unsigned int *` cannot break a call that passes null. It breaks the caller who later passes `addressof` a real `USize`: C writes four of the eight bytes and the rest keep whatever was in the slot, so the caller reads a garbage value.

Public Pony signatures do not have to match the C types. Convert at the FFI call instead — `SSLContext.set_verify_depth` takes a `U32` and passes `depth.i32()`. Where the public type admits values the C type cannot hold, converting silently wraps: a depth above `2^31` arrives as a negative `int`. Validate at the public boundary or say so in the docstring; do not let the conversion be the whole answer.

## Key Files

| File | Role |
|---|---|
| `ssl/net/_ssl_init.pony` | SSL library initialization (threading model differs by version) |
| `ssl/net/ssl_context.pony` | Context management, ALPN setup, TLS version control |
| `ssl/net/ssl.pony` | SSL session — handshake, read/write, certificate verification |
| `ssl/net/alpn_protocol_notify.pony` | `ALPNProtocolNotify` interface for learning the negotiated protocol |
| `ssl/net/alpn_protocol_resolver.pony` | `ALPNProtocolResolver` interface and the standard resolver |
| `ssl/net/alpn.pony` | ALPN wire types, match-result codes, and protocol-list encoding |
| `ssl/net/x509.pony` | Certificate name extraction and hostname matching |
| `ssl/crypto/digest.pony` | Hash digests (MD5, SHA family, SHAKE) via EVP API |
| `ssl/crypto/hmac_sha256.pony` | HMAC-SHA-256 message authentication (RFC 2104) |
| `ssl/crypto/pbkdf2_sha256.pony` | PBKDF2 key derivation with HMAC-SHA-256 (RFC 2898, OpenSSL 1.1.x+/LibreSSL) |
| `ssl/crypto/rand_bytes.pony` | Cryptographically secure random byte generation |
