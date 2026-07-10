## Rename the SSL, TLS and DTLS version primitives

The twelve primitives you hand to `SSLContext.set_min_proto_version` and `set_max_proto_version` spelled their acronyms `Ssl`, `Tls` and `Dtls`. Everything else in the package spells them out — `SSLContext`, `SSLConnection`, `SSLReady`. The version primitives do now too.

| Before | After |
| --- | --- |
| `SslAutoVersion` | `SSLAutoVersion` |
| `Ssl3Version` | `SSL3Version` |
| `Tls1Version` | `TLS1Version` |
| `Tls1u1Version` | `TLS1u1Version` |
| `Tls1u2Version` | `TLS1u2Version` |
| `Tls1u3Version` | `TLS1u3Version` |
| `TlsMinVersion` | `TLSMinVersion` |
| `TlsMaxVersion` | `TLSMaxVersion` |
| `Dtls1Version` | `DTLS1Version` |
| `Dtls1u2Version` | `DTLS1u2Version` |
| `DtlsMinVersion` | `DTLSMinVersion` |
| `DtlsMaxVersion` | `DTLSMaxVersion` |

```pony
// Before
ctx.set_min_proto_version(Tls1u2Version())?
ctx.set_max_proto_version(SslAutoVersion())?

// After
ctx.set_min_proto_version(TLS1u2Version())?
ctx.set_max_proto_version(SSLAutoVersion())?
```

The values and the behavior are unchanged. Rename the call sites and you are done.
