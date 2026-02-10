## Fix set_client_verify(false) not disabling hostname verification

When `set_client_verify(false)` was called on an `SSLContext`, the OpenSSL peer certificate verification was correctly disabled, but hostname verification still ran when a hostname was passed to `SSLContext.client(hostname)`. This meant connections would fail if the server certificate didn't have a SAN or CN matching the hostname, even with verification explicitly disabled.

Hostname verification is now correctly skipped when `set_client_verify(false)` is set.
