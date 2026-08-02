## Fix read and alpn_selected returning data from authentication-failed sessions

Calling `read` on a session in `SSLAuthFail` overwrote the state with `SSLError`, so code that branched on the state to distinguish authentication failures from other errors lost the distinction after the first `read`. Calling `alpn_selected` on the same session returned the ALPN protocol the rejected peer had negotiated. Calling `receive` accepted ciphertext from a peer whose identity had been rejected.

All three methods now return immediately when the session has already failed: `read` and `alpn_selected` return `None`, and `receive` does nothing.
