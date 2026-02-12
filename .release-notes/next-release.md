## Add HMAC-SHA-256 primitive

`HmacSha256` computes HMAC message authentication codes using SHA-256 (RFC 2104):

```pony
let mac = HmacSha256("secret-key", "Hello, World!")
```

## Add PBKDF2-SHA-256 primitive

`Pbkdf2Sha256` derives keys from passwords using PBKDF2 with HMAC-SHA-256 (RFC 2898). Requires OpenSSL 1.1.x or 3.0.x:

```pony
let key = Pbkdf2Sha256("password", "salt", 4096, 32)?
```

## Add RandBytes primitive

`RandBytes` generates cryptographically secure random bytes:

```pony
let nonce = RandBytes(24)?
```
