primitive SSLAutoVersion fun val apply(): ULong => 0x0

primitive SSL3Version    fun val apply(): ULong => 0x300
primitive TLS1Version    fun val apply(): ULong => 0x301
primitive TLS1u1Version  fun val apply(): ULong => 0x302
primitive TLS1u2Version  fun val apply(): ULong => 0x303
primitive TLS1u3Version  fun val apply(): ULong => 0x304
primitive DTLS1Version   fun val apply(): ULong => 0xFEFF
primitive DTLS1u2Version fun val apply(): ULong => 0xFEFD

primitive TLSMinVersion  fun val apply(): ULong => TLS1Version()
primitive TLSMaxVersion  fun val apply(): ULong => TLS1u3Version()
primitive DTLSMinVersion fun val apply(): ULong => DTLS1Version()
primitive DTLSMaxVersion fun val apply(): ULong => DTLS1u2Version()
