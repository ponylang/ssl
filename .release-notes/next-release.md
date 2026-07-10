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

A disposed context is now inert, and every backend treats it the same. `alpn_set_resolver` and `alpn_set_client_protocols` return `false`. `set_min_proto_version` and `set_max_proto_version` raise an error, and `get_min_proto_version` and `get_max_proto_version` return `SSLAutoVersion`. `set_authority` raises an error whether or not you hand it a file.

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

## Allow non-mutating methods to be called on a val receiver

`SSLContext.get_min_proto_version`, `SSLContext.get_max_proto_version` and `SSL.can_send` read their receiver and change nothing, but each was declared `fun ref`, which a `val` receiver cannot call.

That mattered for the getters, because configuring a context and then holding it `val` is what `SSLContext.client` and `SSLContext.server` require, so neither getter could be called on the context shape you end up with:

```pony
let ctx =
  recover val
    SSLContext .> set_authority(auth_file)?
  end

// Before: does not compile.
// After: reads the minimum the context was configured with.
let minimum = ctx.get_min_proto_version()
```

All three now take any receiver. Code that already called them on a mutable receiver needs no change.

## Fix leaks when loading Windows root certificates fails

On Windows, `SSLContext.set_authority(None, None)` loads the system root certificates. Two of its failure paths leaked.

When it could not allocate the certificate store to copy the roots into, it raised an error and left the system certificate store open.

When adding one of the certificates failed partway through, it raised an error and abandoned the certificate it was reading at the time. Windows leaves that one to the caller to release, so its memory was never given back, and the system store's memory could not be released either while it was outstanding.

Both are released now before the error reaches the caller. Only Windows was affected, and only when one of those two calls failed.

## Fix a potential use-after-free in ALPN protocol selection

When a server selected an ALPN protocol, OpenSSL was left with a pointer to memory that could be freed before OpenSSL read it. No SSL backend the library supports reads it late enough for that to happen, so it never crashed, but the bug was real.

One thing changes for you: if you set your own resolver with `SSLContext.alpn_set_resolver` and it returns a protocol the client did not offer, the handshake now fails instead of continuing. `ALPNStandardProtocolResolver` is unaffected.


## Make Digest and HmacSha256 raise on failure

`Digest` and `HmacSha256` now raise when OpenSSL cannot do what you asked, where before they returned a wrong result with no error. Three calls gained a `?`: constructing a `Digest`, `Digest.final`, and `HmacSha256`. `Digest.append` was already partial.

```pony
// Before
let digest = Digest.sha256()
digest.append(data)?
let hash = digest.final()

let mac = HmacSha256(key, message)

// After
let digest = Digest.sha256()?
digest.append(data)?
let hash = digest.final()?

let mac = HmacSha256(key, message)?
```

Constructing a `Digest` now raises if OpenSSL cannot allocate its context, rather than returning a digest that fails on every later call. When `HmacSha256` raises, reject the message. Do not fall back to a code of your own — a code you make up is one an attacker can send you.

## Fix HmacSha256 returning an all-zero code when it fails

`HmacSha256` returned thirty-two zero bytes when it could not compute the code, instead of failing. Thirty-two zero bytes is a value an attacker can send, so a program that checks a message by comparing a fresh code against a supplied one would accept a forgery whenever its own computation failed.

It was reachable with ordinary input: computing the code of an empty key and an empty message returned all zeros. `HmacSha256` now returns the real code and raises when the computation actually fails.

## Fix Digest returning a wrong hash or crashing when OpenSSL fails

`Digest` could return a hash of the wrong bytes, or crash while being created, when an OpenSSL call inside it failed.

`final` returned a block of memory as the hash without checking that OpenSSL had written it, so a failed call returned whatever that memory held — a wrong hash, and a leak of whatever was last in it. Creating a digest crashed when OpenSSL could not allocate its working context.

A digest now raises rather than returning a wrong hash, and one that could not be created reports it at the first `append` or `final` rather than crashing.

## Fix crypto functions truncating a length too large for an int

`RandBytes`, `HmacSha256` and `Pbkdf2Sha256` silently truncated a length that did not fit the C `int` OpenSSL takes. `RandBytes`, asked for a number of bytes past four gigabytes, returned a buffer of that size with only a handful of random bytes in it and the rest zero, and reported success.

These functions now raise on a length larger than an `int` can hold, before allocating anything.
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

