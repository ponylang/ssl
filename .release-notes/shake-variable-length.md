## Add variable-length output support to SHAKE digests

The `shake128` and `shake256` constructors on `Digest` now accept an optional `size` parameter that controls the output length in bytes. The defaults match the previous fixed sizes (16 bytes for SHAKE128, 32 for SHAKE256), so existing code is unaffected.

Variable-length output requires OpenSSL 3.0.x. On OpenSSL 1.1.x, the default size is always used regardless of the parameter value.

```pony
// 64-byte SHAKE256 digest (OpenSSL 3.0.x)
let d = Digest.shake256(64)
d.append("input data")?
let hash: Array[U8] val = d.final()  // 64 bytes
```
