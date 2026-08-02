## Add SSL.shutdown

Calling `SSL.shutdown` queues a TLS `close_notify` alert into the session's output BIO. The alert bytes come out through `send`, the same way handshake and application data do.

```pony
session.shutdown()
while session.can_send() do
  transport.write(session.send()?)
end
```

Without an alert on the wire before the transport closes, an OpenSSL peer that reads TCP EOF without an alert reports `SSL_R_UNEXPECTED_EOF_WHILE_READING`, its signal for a truncated stream. RFC 8446 §6.1 requires each party to send `close_notify` before closing its write side.

`shutdown` runs from `SSLReady` (initiating) and from `SSLPeerClosed` (reciprocating the peer's alert). If `SSL_shutdown` fails, the session moves to `SSLError` — the caller draining the output BIO sees no bytes and can react instead of closing the transport with silent truncation.

After `shutdown` returns, `write` on the session raises. This package does not offer TLS half-close: application writes after our own or the peer's `close_notify` are refused.

`SSLConnection` does not send `close_notify` on close in either direction — its `closed` hook fires after the transport is gone. A protocol that needs the alert on the wire has to use `SSL` directly.

## Split SSLPeerClosed from SSLError

A session whose peer sent `close_notify` now has state `SSLPeerClosed`. That case used to fold into `SSLError` alongside decryption failures and dropped connections, so a clean end of stream and a failure were indistinguishable.

`SSL.read` on a session in `SSLPeerClosed` still surfaces any bytes decrypted before the peer's `close_notify` — the same way `SSLError` does. The next read past those bytes returns `None`.

`SSL.receive` on a session in `SSLPeerClosed` drops the bytes. `SSL.write` raises, as on any non-`SSLReady` state.

`SSLPeerClosed` is added to the public `SSLState` union. A caller that matched on `SSLError` after `SSL.read` to detect any end of a session needs an added arm; a `match \exhaustive\` on `SSLState` needs an arm for the new variant.

Before:

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
