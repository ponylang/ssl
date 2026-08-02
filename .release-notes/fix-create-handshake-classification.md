## Fix client sessions not reporting immediate handshake failures

A client session created from a context with no usable protocol version or cipher suite stayed in `SSLHandshake` after construction instead of reporting `SSLError`. The session appeared to be negotiating when it could never succeed.
