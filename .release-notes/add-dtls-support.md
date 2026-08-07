## Add DTLSContext and DTLS for datagram TLS

`DTLSContext` and `DTLS` bring DTLS (datagram TLS) support. DTLS provides the same authentication and encryption as TLS over unreliable transports like UDP.

The API mirrors `SSLContext` and `SSL`. A `DTLSContext` creates client or server `DTLS` sessions; the session encrypts and decrypts application data through `write`, `read`, `receive`, and `send`, with the same return types (`SSLReceiveResult`, `SSLReadResult`).

```pony
let ctx = recover val
  let c = DTLSContext
  c.set_cert(
    FilePath(auth, "cert.pem"),
    FilePath(auth, "key.pem"))?
  c.set_authority(FilePath(auth, "ca.pem"))?
  c.set_client_verify(true)
  c
end

let session = ctx.client("server.example.com")?

// Feed encrypted bytes from the network into the session
match session.receive(data_from_udp)
| SSLReady => None // handshake complete
| SSLAccepted => None // still handshaking
| SSLAuthFail => // peer certificate rejected
| SSLError => // protocol error
end

// Encrypt application data for sending
session.write("hello")?
match session.send()
| let out: Array[U8] iso => send_over_udp(consume out)
end

// Read decrypted application data
match session.read()
| let plaintext: Array[U8] iso => // use it
end
```

`DTLSContext` and `SSLContext` are separate types because a TLS context cannot create a DTLS session and vice versa. Using separate types makes the wrong combination a compile error.
