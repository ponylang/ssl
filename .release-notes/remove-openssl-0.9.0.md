## Remove OpenSSL 0.9.0 support

Support for `-Dopenssl_0.9.0` has been removed. OpenSSL 0.9.8 reached end-of-life in January 2016 and has 64 known CVEs. It should not be used.

LibreSSL users who were previously building with `-Dopenssl_0.9.0` should switch to `-Dlibressl`.

If you are using OpenSSL, switch to `-Dopenssl_1.1.x` or `-Dopenssl_3.0.x` depending on your installed version.
