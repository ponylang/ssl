## Fix SSL.write silently losing data when encryption fails

`SSL.write` could report success when it encrypted nothing. A TLS 1.2 peer that started a renegotiation triggered this: the session was still `SSLReady`, but the write produced no ciphertext and the payload was gone. `write` now raises an error when it cannot encrypt the data. A fatal encryption failure also sets the session to `SSLError`.
