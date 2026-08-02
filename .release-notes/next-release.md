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

## Fix read and alpn_selected returning data from authentication-failed sessions

Calling `read` on a session in `SSLAuthFail` overwrote the state with `SSLError`, so code that branched on the state to distinguish authentication failures from other errors lost the distinction after the first `read`. Calling `alpn_selected` on the same session returned the ALPN protocol the rejected peer had negotiated. Calling `receive` accepted ciphertext from a peer whose identity had been rejected.

All three methods now return immediately when the session has already failed: `read` and `alpn_selected` return `None`, and `receive` does nothing.

## Fix ssl/net silently losing data past two gibibytes

Passing more than two gibibytes through an SSL session could silently lose data. `write` passed only a small fraction of a large buffer to the session. `receive` passed only part of a large ciphertext block to the session. `send` did not return ciphertext from a session whose output had grown past two gibibytes. `read` with a large `expect` allocated more memory than it filled. All four methods now work correctly with data of any size.

## Fix SSL.write silently losing data when encryption fails

`SSL.write` could report success when it encrypted nothing. A TLS 1.2 peer that started a renegotiation triggered this: the session was still `SSLReady`, but the write produced no ciphertext and the payload was gone. `write` now raises an error when it cannot encrypt the data. A fatal encryption failure also sets the session to `SSLError`.

## Fix client sessions not reporting immediate handshake failures

A client session created from a context with no usable protocol version or cipher suite stayed in `SSLHandshake` after construction instead of reporting `SSLError`. The session appeared to be negotiating when it could never succeed.

## Fix SSLConnection calling auth_failed twice for one failure

`SSLConnection` called `auth_failed` on the wrapped notify twice for a single authentication failure. The second call happened during `closed`. A notify that counted calls or performed side effects on each `auth_failed` received two calls.

## Fix SSLContext accepting an inverted protocol version range

`set_min_proto_version(TLS1u3Version())` followed by `set_max_proto_version(TLS1u2Version())` passed without raising. Every session from that context then failed its handshake with "no protocols available." Both setters now raise when the new value would leave the minimum above the maximum.

