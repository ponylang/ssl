## Fix crashes when using a disposed SSL context

Calling a method on an `SSLContext` after `dispose()` could crash the program. `alpn_set_resolver` and `alpn_set_client_protocols` crashed against every SSL backend. `set_min_proto_version`, `set_max_proto_version`, `get_min_proto_version` and `get_max_proto_version` crashed against LibreSSL. `set_authority(None, None)`, which loads the system root certificates, crashed on Windows.

A disposed context is now inert, and every backend treats it the same. `alpn_set_resolver` and `alpn_set_client_protocols` return `false`. `set_min_proto_version` and `set_max_proto_version` raise an error, and `get_min_proto_version` and `get_max_proto_version` return `SslAutoVersion`. `set_authority` raises an error whether or not you hand it a file.

`client` and `server` on a disposed context raised an error, which is what they should do, and could then crash the program the next time the garbage collector ran. The crash landed far from the call that caused it. That no longer happens.
