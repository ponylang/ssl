## Add SSL.shutdown

`SSL.shutdown` sends a TLS `close_notify` to the peer. Call it before closing the transport, so a peer reading TCP EOF sees an orderly end of stream instead of a truncation. Without it, an OpenSSL peer treats the missing alert as an attack and reports the stream as truncated.

```pony
session.shutdown()
while session.can_send() do
  transport.write(session.send()?)
end
```

`shutdown` runs from `SSLReady` (initiating) and from `SSLPeerClosed` (reciprocating the peer's alert). Repeating the call is a no-op. After it returns, `write` on the session raises: this package does not offer TLS half-close.

`SSLConnection` does not send `close_notify` on close, in either direction — its `closed` hook fires after the transport is gone. A protocol that needs the alert on the wire has to use `SSL` directly.

## Split SSLPeerClosed from SSLError

A session whose peer sent `close_notify` now reports `SSLPeerClosed`, not `SSLError`. Before, a clean end of stream and a failure looked the same to a caller matching on state.

A caller that matched on `SSLError` to detect any end of a session needs an added arm; a `match \exhaustive\` on `SSLState` needs one too. Before:

```pony
match session.state()
| SSLReady => None
| SSLError => // any end of session
end
```

After:

```pony
match session.state()
| SSLReady => None
| SSLPeerClosed => // peer closed cleanly
| SSLError => // decryption failure, syscall error, dropped connection
end
```
