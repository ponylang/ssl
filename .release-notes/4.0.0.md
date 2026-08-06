## Add SSL.close() and SSLClosed for orderly TLS shutdown

`SSL.close()` sends a TLS `close_notify` alert so the peer sees a clean end of session instead of a protocol error. `SSLClosed` is the new state for a cleanly closed session.

## Replace state polling with return values from receive, read, and send

`state()`, `can_send()`, `SSLState`, `SSLHandshake`, and `SSLDisposed` are removed. The return values of `receive()`, `read()`, and `send()` carry the outcome of each operation. `InvalidOperation` signals a call on a session that is no longer operational (disposed).

`receive(data)` returns `SSLReceiveResult`:

```pony
// Before
ssl.receive(data)
match ssl.state()
| SSLHandshake => // ...
| SSLReady => // ...
| SSLAuthFail => // ...
| SSLError => // ...
| SSLDisposed => // ...
end

// After
match ssl.receive(data)
| SSLAccepted => None
| SSLReady => // ...
| SSLAuthFail => // ...
| SSLError => // ...
| InvalidOperation => // ...
end
```

`read()` returns `SSLReadResult`. A clean peer closure is now `SSLClosed`; a protocol error is `SSLError`. Previously both returned `None`, and the caller had to check `state()` to distinguish them:

```pony
// Before
match ssl.read()
| let data: Array[U8] iso => // ...
| None => // ...
end

// After
match ssl.read()
| let data: Array[U8] iso => // ...
| None => // ...
| SSLClosed => // ...
| SSLError => // ...
| InvalidOperation => // ...
end
```

`send()` returns `(Array[U8] iso^ | None)` and no longer raises:

```pony
// Before
while ssl.can_send() do
  let data = ssl.send()?
  conn.write(consume data)
end

// After
while true do
  match ssl.send()
  | let data: Array[U8] iso =>
    conn.write(consume data)
  | None => break
  end
end
```

## Fix alpn_selected() returning a protocol from a failed session

`alpn_selected()` on a failed session returned the protocol that was negotiated before the failure. The session was not usable, but the caller got back a negotiated protocol as if it were.
