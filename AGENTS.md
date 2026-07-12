# SSL

Pony bindings for OpenSSL and LibreSSL: SSL networking (`ssl/net`) and cryptographic primitives (`ssl/crypto`).

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

## Building and testing

Always use `make`, not `ponyc` directly; the Makefile runs `corral` to fetch dependencies first.

```
make test config=debug ssl=<version>
make test-one t=TestName ssl=3.0.x   # run a single test by name
make lint                            # pony-lint the sources; no ssl= needed
```

`ssl=` is required for building and testing:

| `ssl=` value | Backend |
|---|---|
| `4.0.x` | OpenSSL 4.x |
| `3.0.x` | OpenSSL 3.x |
| `1.1.x` | OpenSSL 1.1.x |
| `libressl` | LibreSSL |

Windows (`make.ps1`) always uses LibreSSL, with the define hardcoded and prebuilt binaries downloaded by `.ci-scripts/windows-install-libressl.ps1`.

## LibreSSL divergences from OpenSSL 1.1.x

LibreSSL is mostly OpenSSL 1.1.x-compatible, but five differences need their own code paths:

1. **`sk_pop`/`sk_free`** — LibreSSL keeps the old names (no `OPENSSL_` prefix).
2. **`SSL_CTX_set_options`/`SSL_CTX_clear_options`** — macros in LibreSSL, not functions. Pony FFI can't call a macro, so LibreSSL goes through `SSL_CTX_ctrl`.
3. **`SSL_has_pending`** — absent in LibreSSL; only `SSL_pending` exists.
4. **`SSL_get_peer_certificate`** — LibreSSL keeps the pre-3.0.x name, not `SSL_get1_peer_certificate`.
5. **`OPENSSL_INIT_new`/`OPENSSL_INIT_free`** — absent; init calls `OPENSSL_init_ssl` directly with no settings object.

## Dispose and `_final`

`dispose()` frees the OpenSSL handle and nulls the pointer field, so any later call hands OpenSSL a null. Most of the C functions dereference it without checking, and the ones that don't vary by backend — `SSL_CTX_ctrl` returns 0 for a null context on OpenSSL but dereferences it on LibreSSL. Check `is_null()` before calling into OpenSSL; don't count on a backend being forgiving.

Pony registers a `_final` when it allocates the object, not when the constructor returns, so `_final` runs even on an object whose constructor raised. A pointer field that `_final` frees needs a null default at its declaration, or it frees whatever was left in the recycled heap slot.

## Version-specific code (`ifdef`)

FFI `use` declarations and `ifdef` blocks are guarded by the `ssl=` defines, and every `ifdef` chain ends with a `compile_error` catch-all so a missing define fails the build.

**One symbol whose C signature changes by version needs two `use` statements, and the second guard must exclude the first.** ponyc resolves an FFI call by enumerating every combination of the defines named in the guards, not just the one the build passes, and nothing tells it the `ssl=` defines are mutually exclusive — so overlapping guards give "Multiple possible declarations for FFI call":

```pony
use @SSL_CTX_set_options[U64](ctx: Pointer[_SSLContext] tag, opts: U64) if "openssl_3.0.x" or "openssl_4.0.x"
use @SSL_CTX_set_options[ULong](ctx: Pointer[_SSLContext] tag, opts: ULong) if "openssl_1.1.x" and not ("openssl_3.0.x" or "openssl_4.0.x")
```

The call site needs an `ifdef` split too, since Pony won't implicitly convert one call expression to both parameter types. Adding a new SSL define means adding it to the exclusion list; forgetting is safe, because the enumeration finds the overlap and fails the build on every backend.

## FFI type mapping

Declare the Pony type that matches the C type in the header, not one that happens to be the same width on the platforms CI builds:

| C type | Pony type |
|---|---|
| `int` / `unsigned int` | `I32` / `U32` |
| `long` / `unsigned long` | `ILong` / `ULong` |
| `size_t` | `USize` |
| `uint64_t` | `U64` |
| pointer to an opaque C struct | `Pointer[_Name]` (declare a phantom primitive) |
| `void *`, or a pointer only ever passed as null | `Pointer[None]` |
| pointer to bytes | `Pointer[U8]` |

`ILong`/`ULong` track C's `long` — 32 bits on Windows and on 32-bit targets, 64 on 64-bit Unix — and `USize` tracks pointer-width `size_t`; neither stands in for `uint64_t`. Reaching for `ULong` because it is 64 bits on the platform in front of you passes 32 bits on every 32-bit build. A `Pointer[X]`'s element type never reaches the ABI, so a wrong one survives a null call but corrupts a later caller who passes `addressof` a real value. Public Pony signatures need not match the C types — convert at the call (`set_verify_depth` takes a `U32` and passes `depth.i32()`) — but a conversion that can wrap (a depth above `2^31` arriving negative) must be validated at the public boundary or called out in the docstring.

## Conventions

- `\nodoc\` on test classes, actors, and primitives.
