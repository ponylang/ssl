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

