## Fix crash when using a disposed SSL session

Calling `read`, `receive`, `can_send`, or `send` on an `SSL` session that had already been disposed crashed the program.

A disposed session is now inert. `read` returns `None`, `receive` does nothing, `can_send` returns `false`, `alpn_selected` returns `None`, and `write` and `send` raise an error. `state` is the one exception: it keeps returning the state the session was in when it was disposed.

Two behavior changes come with the crash fix. `write` on a disposed session used to return as though it had written the data, and nothing was written; it now raises an error. `read` on a disposed session that still held decrypted bytes from an incomplete `expect` frame used to hand those bytes back; it now returns `None`.

Anything built on `SSLConnection` is unaffected: it wraps every `write` in a `try`, and it disposes a session only once the connection has closed and stopped reading. Code that uses `SSL` directly and discards the error from `write` was silently dropping data and now gets an error.
