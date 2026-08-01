## Fix connections being closed after an unrelated SSL failure

A failed OpenSSL operation left error state on the scheduler thread that ran it. The next SSL session to read on that thread was treated as failed even when nothing was wrong with it, and its connection was closed. A rejected handshake was enough to start it, and so was a bad certificate path or an unusable cipher string given to `SSLContext`. A failed operation now affects only the session it happened on.

## Fix SSL sessions returning uninitialized memory

`SSL.read` and `SSL.send` could return uninitialized memory. They no longer do.

## Fix handshake failures being reported as authentication failures

`SSLAuthFail` was documented as the peer's certificate failing to verify, but a session reported it after failures that had nothing to do with authenticating the peer: a peer that sent something other than TLS to a TLS port, or two peers with no protocol version in common.

A session now reports `SSLAuthFail` when it required a certificate from its peer and did not get an acceptable one:

- the peer's certificate chain did not verify
- the peer's certificate was not valid for the hostname the session was created with
- the peer presented no certificate at all

Every other failure reports `SSLError`, including a peer that does not speak TLS, a peer that shares no protocol version with the session, and a peer that rejects the certificate the session presented.

## Report SSLAuthFail only for a peer certificate the session would not accept

Three things that reported `SSLAuthFail` before this release report `SSLError` now, and no compile error will point you at them.

A peer that presents a certificate it cannot prove it holds — which is what an impersonator using a copy of a public certificate produces — and a peer whose certificate will not parse are the first two. There is no way to tell either of them from any other `SSLError` through the session state.

A session created with verification off is the third. That includes a server built without `set_server_verify(true)`, which is the default: it sends no certificate request, so it has no peer identity to reject.

If you wrap a protocol in `SSLConnection`, what changes is whether `auth_failed` runs before `closed`. `SSLConnection` calls `auth_failed` for `SSLAuthFail` and nothing for `SSLError`, and closes the connection on both, so a protocol that used to get `auth_failed` for one of these now gets `closed` on its own. A `closed` with no `connected` or `accepted` before it means the handshake failed. The reverse does not hold: under TLS 1.3 a session can finish its own side of the handshake before its peer's rejection reaches it, so a peer that rejected the connection can still produce `connected` and then `closed`.
## Fix unproven peer certificates reporting SSLError instead of SSLAuthFail

A peer that presents a certificate it cannot prove it holds — an impersonator with a copy of the certificate but not the matching private key — now reports `SSLAuthFail`. Previously it reported `SSLError`, so `SSLConnection` closed the connection without calling `auth_failed` on the wrapped notify.

## Fix receive reporting inconsistent state when a callback contaminates the error queue

A callback running during the TLS handshake — such as an ALPN resolver — could change whether `auth_failed` fired on the connection notify. The same handshake failure could produce `SSLAuthFail` or `SSLError` depending on what the callback happened to call internally, because one OpenSSL error code bypassed the authentication-failure classification that the other went through. Both error codes now take the same classification path, so the reported state depends on what failed, not on what the callback did.

