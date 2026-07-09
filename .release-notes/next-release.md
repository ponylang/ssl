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
