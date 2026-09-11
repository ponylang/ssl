# SSL

Pony cryptographic primitives wrapping OpenSSL and LibreSSL (`ssl/crypto`).

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

## Prose model

If you are running on an Anthropic model, use `claude-opus-4-6` for writing comments, documentation, and other prose. Prose quality from Anthropic models dropped starting with Opus 4.7 and has gotten worse with each subsequent release.

## Linting

Run `make lint` before considering any work done. Fix all issues it reports. `make lint` runs pony-lint, which checks for style and correctness problems in Pony source files. A clean lint run is part of "done" — don't open a PR or report completion with lint issues outstanding.

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

## `_final`

Pony registers a `_final` when it allocates the object, not when the constructor returns, so `_final` runs even on an object whose constructor raised. A pointer field that `_final` frees needs a null default at its declaration, or it frees whatever was left in the recycled heap slot.

## Version-specific code (`ifdef`)

FFI `use` declarations and `ifdef` blocks are guarded by the `ssl=` defines, and every `ifdef` chain ends with a `compile_error` catch-all so a missing define fails the build.

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

`ILong`/`ULong` track C's `long` — 32 bits on Windows and on 32-bit targets, 64 on 64-bit Unix — and `USize` tracks pointer-width `size_t`; neither stands in for `uint64_t`. Reaching for `ULong` because it is 64 bits on the platform in front of you passes 32 bits on every 32-bit build. A `Pointer[X]`'s element type never reaches the ABI, so a wrong one survives a null call but corrupts a later caller who passes `addressof` a real value. Public Pony signatures need not match the C types — convert at the call — but a conversion that can wrap must be validated at the public boundary or called out in the docstring.

## Conventions

- `\nodoc\` on test classes, actors, and primitives.
