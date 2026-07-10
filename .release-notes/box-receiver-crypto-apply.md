## Require a box receiver for ssl/crypto's apply methods

The `apply` methods on the eight one-shot hash functions (`MD4`, `MD5`, `RIPEMD160`, `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`), on `ToHexString`, `RandBytes`, `HmacSha256` and `Pbkdf2Sha256`, and on the `HashFn` interface, took a `tag` receiver. They take a `box` receiver now.

Calling any of them the way you normally would — `MD5("data")`, `HmacSha256(key, message)?` — needs no change. Writing your own `HashFn` needs no change either: a `fun tag apply` still satisfies the interface, and a `fun box apply`, which did not satisfy the `tag` interface before, satisfies it now too.

The one thing that stops compiling is a reference typed `tag`, because a `box` method cannot be called through a `tag`:

```pony
// Was fine, now a compile error:
let hash: HashFn tag = SHA256
hash("data")

// Type the reference val (or box):
let hash: HashFn val = SHA256
hash("data")
```
