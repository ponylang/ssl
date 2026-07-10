## Fix crash when using a disposed SSL session

Calling `read`, `receive`, `can_send`, or `send` on an `SSL` session that had already been disposed crashed the program.

A disposed session is now inert. `read` returns `None`, `receive` and `write` do nothing, `can_send` returns `false`, `alpn_selected` returns `None`, and `send` raises an error, the same as it does for any session with nothing left to send.

`read` on a disposed session that still held decrypted bytes from an incomplete `expect` frame used to hand those bytes back. It now returns `None`, like every other read of a disposed session.

## Add SSLDisposed to SSLState

`SSL.state()` used to keep returning the state a session was in when it was disposed. A session that finished its handshake and was then disposed still reported `SSLReady`, so no part of the API distinguished a freed session from a live one.

`SSLState` has a new member, `SSLDisposed`. `SSL.dispose()` puts the session in it, whatever state the session was in before.

Code that wraps a protocol in `SSLConnection` needs no change; we updated `SSLConnection` for the new state.

Code that matches on `SSL.state()` exhaustively needs a new branch:

```pony
// Before
match \exhaustive\ ssl.state()
| SSLHandshake => None
| SSLAuthFail => None
| SSLReady => None
| SSLError => None
end

// After
match \exhaustive\ ssl.state()
| SSLHandshake => None
| SSLAuthFail => None
| SSLReady => None
| SSLError => None
| SSLDisposed => None
end
```

Code that read `state()` after a dispose to recover the state the session was in before no longer can. `state()` reports `SSLDisposed` from that point on. Read the state before disposing the session.
## Fix crashes when using a disposed SSL context

Calling a method on an `SSLContext` after `dispose()` could crash the program. `alpn_set_resolver` and `alpn_set_client_protocols` crashed against every SSL backend. `set_min_proto_version`, `set_max_proto_version`, `get_min_proto_version` and `get_max_proto_version` crashed against LibreSSL. `set_authority(None, None)`, which loads the system root certificates, crashed on Windows.

A disposed context is now inert, and every backend treats it the same. `alpn_set_resolver` and `alpn_set_client_protocols` return `false`. `set_min_proto_version` and `set_max_proto_version` raise an error, and `get_min_proto_version` and `get_max_proto_version` return `SslAutoVersion`. `set_authority` raises an error whether or not you hand it a file.

`client` and `server` on a disposed context raised an error, which is what they should do, and could then crash the program the next time the garbage collector ran. The crash landed far from the call that caused it. That no longer happens.

## Fix allow_tls_v1, allow_tls_v1_1 and allow_tls_v1_2 on 32-bit platforms

`SSLContext.allow_tls_v1`, `SSLContext.allow_tls_v1_1` and `SSLContext.allow_tls_v1_2` did not change the protocol version they name, and left the context with TLS options nobody asked for. A call meant to forbid a version left it allowed, a call meant to allow one left it forbidden, and unrelated TLS features were switched on either way.

This affected 32-bit builds using OpenSSL 3.x or 4.x. 64-bit builds, LibreSSL builds, and OpenSSL 1.1.x builds were never affected.

These methods now change only the protocol version they name.

## Fix ALPN resolver being collected while still in use

Setting an ALPN protocol resolver on an `SSLContext` and then dropping your own reference to it could crash a server. `SSLContext.alpn_set_resolver` hands the resolver to OpenSSL, which keeps a raw pointer to it and calls it during every incoming connection's handshake. Nothing on the Pony side kept the resolver alive, so the garbage collector was free to collect it while OpenSSL still held the pointer. A peer opening a TLS connection then drove the handshake into freed memory.

The resolver now stays alive on its own. The context keeps it alive, and every session made from the context keeps the context alive, so the resolver lives for as long as any session that can use it. There is nothing you have to hold onto by hand.

## Require a val resolver for alpn_set_resolver

`SSLContext.alpn_set_resolver` now takes an `ALPNProtocolResolver val` where it took an `ALPNProtocolResolver box` before, and the `ALPNProtocolResolver` interface is now `val`. An `SSLContext` is shared across actors, so the resolver can run on any of them, and it has to be immutable and safe to share.

`ALPNStandardProtocolResolver` is already `val`, so code using it needs no change. Code that passes a resolver of its own class must pass it as `val`:

```pony
// Before
ctx.alpn_set_resolver(MyResolver)

// After
ctx.alpn_set_resolver(recover val MyResolver end)
```

## Require a val context for SSLContext.client and server

`SSLContext.client` and `SSLContext.server` now need a `val` context where they worked on a mutable one before. Making a session is what keeps the context, and the ALPN resolver it installed with OpenSSL, alive, and a session can only hold the context if it is `val`.

You configure a context and then make sessions from it, so freeze it to `val` once configuration is done:

```pony
// Before
let ctx = SSLContext
ctx.set_authority(auth_file)?
let session = ctx.client(hostname)?

// After
let ctx =
  recover val
    SSLContext .> set_authority(auth_file)?
  end
let session = ctx.client(hostname)?
```

`SSLContext.server` changes the same way. Configuration methods like `set_authority` still need a mutable context, so do all configuration before freezing. A `val` context cannot be disposed, so a context you make sessions from is freed when the garbage collector collects it rather than when you call `dispose`.
## Fix Digest leaking memory when final() is never called

A `Digest` that was built and then dropped without a call to `final()` never gave back the memory it allocated. A program that abandoned digests — because a request was cancelled, or an error was raised partway through — grew its memory use with every digest it dropped.

Dropping a digest without calling `final()` is now safe. The memory comes back when the garbage collector collects the digest. Calling `final()` frees it as before.

