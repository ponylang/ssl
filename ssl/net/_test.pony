use "pony_test"
use "pony_check"
use "itertools"
use "files"
use "net"

use @memset[Pointer[None]](dst: Pointer[None], value: I32, n: USize)
use @pony_ctx[Pointer[None]]()
use @pony_triggergc[None](ctx: Pointer[None])

actor \nodoc\ Main is TestList
  new create(env: Env) => PonyTest(env, this)
  new make() => None

  fun tag tests(test: PonyTest) =>
    test(_TestALPNProtocolListEncoding)
    test(_TestALPNProtocolListDecode)
    test(_TestALPNProtocolListOffsetOf)
    test(Property1UnitTest[Array[String]](_TestALPNProtocolListOffsetOfRoundtrip))
    test(_TestALPNStandardProtocolResolver)
    test(_TestSSLHandshakeInMemory)
    test(_TestSSLDisposeBeforeHandshake)
    test(_TestSSLDisposeTwice)
    test(_TestSSLReadAfterDispose)
    test(_TestSSLReadAfterDisposeWithBufferedFrame)
    test(_TestSSLReceiveAfterDispose)
    test(_TestSSLCanSendAfterDispose)
    test(_TestSSLSendAfterDispose)
    test(_TestSSLWriteAfterDispose)
    test(_TestSSLALPNSelectedAfterDispose)
    test(_TestSSLContextDisposeTwice)
    test(_TestSSLContextALPNSetResolverAfterDispose)
    test(_TestSSLContextALPNFallbackToClientProtocol)
    test(_TestSSLContextALPNUnadvertisedProtocolFails)
    test(_TestSSLContextALPNResolverRootedByContext)
    test(_TestSSLContextALPNResolverRootedBySession)
    test(_TestSSLContextALPNResolverUnreferenced)
    test(_TestSSLContextALPNSetClientProtocolsAfterDispose)
    test(_TestSSLContextSetMinProtoVersionAfterDispose)
    test(_TestSSLContextSetMaxProtoVersionAfterDispose)
    test(_TestSSLContextGetMinProtoVersionAfterDispose)
    test(_TestSSLContextGetMaxProtoVersionAfterDispose)
    test(_TestSSLContextGetMinProtoVersionOnValReceiver)
    test(_TestSSLContextGetMaxProtoVersionOnValReceiver)
    test(_TestSSLCanSendOnValReceiver)
    test(_TestSSLContextSetAuthorityRootCertsAfterDispose)
    test(_TestSSLContextSetAuthorityAfterDispose)
    test(_TestSSLContextSetCertAfterDispose)
    test(_TestSSLContextSetCiphersAfterDispose)
    test(_TestSSLContextSetVerifyDepthAfterDispose)
    test(_TestSSLContextAllowTlsAfterDispose)
    test(_TestSSLContextAllowTlsV1u2)
    test(_TestSSLContextClientAfterDispose)
    test(_TestSSLContextServerAfterDispose)
    test(_TestTCPSSLWritev)
    test(_TestTCPSSLExpect)
    test(_TestTCPSSLMute)
    test(_TestTCPSSLUnmute)
    test(_TestTCPSSLClientVerifyFalseWithHostname)
    test(_TestTCPSSLPeerCertificateVerify)
    test(_TestTCPSSLPeerCertificateHostnameMismatch)
    ifdef windows then
      test(_TestWindowsLoadRootCertificates)
    else
      test(_TestTCPSSLThrottle)
    end
    test(Property1UnitTest[Array[String]](_TestALPNProtocolListRoundTrip))
    test(_TestMatchNameEmptyName)
    test(_TestMatchNameExactCaseInsensitive)
    test(_TestMatchNameNoMatch)
    test(_TestMatchNameIPLiteral)
    test(_TestMatchNameWildcard)
    test(_TestMatchNameWildcardInsufficientLevels)

class \nodoc\ iso _TestALPNProtocolListEncoding is UnitTest
  """
  [Protocol Lists]() are correctly encoded and errors are raised when trying to encode invalid identifiers
  """
  fun name(): String => "net/ssl/_ALPNProtocolList.from_array"

  fun apply(h: TestHelper) =>
    let valid_h2http11 = "\x02h2\x08http/1.1"

    h.assert_error(
      {()? => _ALPNProtocolList.from_array([""])? },
      "raise error on empty protocol identifier")
    h.assert_error(
      {()? => _ALPNProtocolList.from_array(["dummy"; ""])? },
      "raise error when encoding an protocol identifier")
    h.assert_error(
      {()? => _ALPNProtocolList.from_array([])? },
      "raise error when encoding an empty array")

    let id256chars =
      recover val String(256) .> concat(Iter[U8].repeat_value('A'), 0, 256) end
    h.assert_eq[USize](id256chars.size(), USize(256))
    h.assert_error(
      {()? => _ALPNProtocolList.from_array([id256chars])? },
      "raise error on identifier longer than 256 bytes.")
    h.assert_error(
      {()? => _ALPNProtocolList.from_array([id256chars; "dummy"])? },
      "raise error on identifier longer than 256 bytes.")

    try
      h.assert_eq[String](
        _ALPNProtocolList.from_array(["h2"; "http/1.1"])?, valid_h2http11)
    else
      h.fail("failed to encode an array of valid identifiers")
    end

class \nodoc\ iso _TestALPNProtocolListOffsetOf is UnitTest
  """
  `offset_of` finds a protocol name in a protocol list, and raises when the list
  does not contain it.

  The offset it returns is what the ALPN select callback hands to OpenSSL, so a
  wrong offset points OpenSSL at the wrong bytes.
  """
  fun name(): String => "net/ssl/_ALPNProtocolList.offset_of"

  fun apply(h: TestHelper) =>
    let h2_http11 = "\x02h2\x08http/1.1"

    try
      h.assert_eq[USize](
        1, _ALPNProtocolList.offset_of(h2_http11, "h2")?,
        "h2 starts one byte past its length prefix")
      h.assert_eq[USize](
        4, _ALPNProtocolList.offset_of(h2_http11, "http/1.1")?,
        "http/1.1 starts after h2 and its own length prefix")
    else
      h.fail("failed to find a name that is in the list")
    end

    h.assert_error(
      {()? => _ALPNProtocolList.offset_of(h2_http11, "spdy/1")? },
      "raise on a name the list does not contain")

    // A length prefix is what separates names, so a name that appears in the
    // list only as part of a longer name is not in the list.
    h.assert_error(
      {()? => _ALPNProtocolList.offset_of("\x03h2c", "h2")? },
      "h2 is not a prefix match inside h2c")
    h.assert_error(
      {()? => _ALPNProtocolList.offset_of("\x03xh2", "h2")? },
      "h2 is not a suffix match inside xh2")

    // "h2" appears inside "h2c" before it appears as a name of its own. The
    // offset has to be the name's, not the first place the bytes turn up.
    try
      h.assert_eq[USize](
        5, _ALPNProtocolList.offset_of("\x03h2c\x02h2", "h2")?,
        "a name that a longer name contains is found at its own offset")
    else
      h.fail("failed to find h2 past a longer name containing it")
    end

    try
      h.assert_eq[USize](
        1, _ALPNProtocolList.offset_of("\x02h2\x02h2", "h2")?,
        "a repeated name is found at the first of its offsets")
    else
      h.fail("failed to find a repeated name")
    end

    h.assert_error(
      {()? => _ALPNProtocolList.offset_of("", "h2")? },
      "raise on an empty list")
    h.assert_error(
      {()? => _ALPNProtocolList.offset_of("\x08http", "http")? },
      "raise on a list whose length prefix runs past its end")
    h.assert_error(
      {()? => _ALPNProtocolList.offset_of("\x00", "")? },
      "raise on a zero length prefix")

class \nodoc\ iso _TestALPNProtocolListOffsetOfRoundtrip is Property1[Array[String]]
  """
  Every name `from_array` packs into a list is found by `offset_of`, at an offset
  whose bytes are that name.
  """
  fun name(): String => "net/ssl/_ALPNProtocolList.offset_of/property/roundtrip"

  fun gen(): Generator[Array[String]] =>
    Generators.array_of[String](
      Generators.ascii_printable(1, 20) where min = 1, max = 5)

  fun ref property(sample: Array[String], h: PropertyHelper) ? =>
    let list = _ALPNProtocolList.from_array(sample)?

    for protocol in sample.values() do
      let offset = _ALPNProtocolList.offset_of(list, protocol)?

      // The byte before a name is its length. Checking it says the offset is
      // the start of a name and not somewhere in the middle of one, which is
      // the only way `offset_of` can be wrong while still matching the bytes.
      h.assert_eq[USize](
        protocol.size(), USize.from[U8](list(offset - 1)?),
        "the byte before the offset should be the name's length")
      h.assert_true(
        list.at(protocol, offset.isize()),
        "the bytes at the offset should be the protocol name")
    end

class \nodoc\ iso _TestALPNProtocolListDecode is UnitTest
  fun name(): String => "net/ssl/_ALPNProtocolList.to_array"

  fun apply(h: TestHelper) =>
    let valid_h2http11 = "\x02h2\x08http/1.1"
    try
      let decoded = _ALPNProtocolList.to_array(valid_h2http11)?
      h.assert_eq[USize](decoded.size(), USize(2))
      h.assert_eq[ALPNProtocolName](decoded(0)?, "h2")
      h.assert_eq[ALPNProtocolName](decoded(1)?, "http/1.1")
    else
      h.fail("failed to decode a valid protocol list")
    end

    h.assert_error(
      {()? => _ALPNProtocolList.to_array("")? },
      "raise error when decoding an empty protocol list")
    h.assert_error(
      {()? => _ALPNProtocolList.to_array("\x03h2")? },
      "raise error on malformed data")
    h.assert_error(
      {()? => _ALPNProtocolList.to_array("\x00")? },
      "raise error on malformed data")
    h.assert_error(
      {()? => _ALPNProtocolList.to_array("\x01A\x00")? },
      "raise error on malformed data")
    h.assert_error(
      {()? => _ALPNProtocolList.to_array("\x01A\x01")? },
      "raise error on malformed data")

class \nodoc\ iso _TestALPNStandardProtocolResolver is UnitTest
  fun name(): String => "net/ssl/StandardALPNProtocolResolver"

  fun apply(h: TestHelper) =>
    fallback_case(h)
    failure_case(h)
    match_cases(h)

  fun fallback_case(h: TestHelper) =>
    let resolver = ALPNStandardProtocolResolver(["h2"])

    match resolver.resolve(["http/1.1"])
    | "http/1.1" => None
    else
      h.fail(
        "ALPNStandardProtocolResolver didn't fall back to clients "
        + "first identifier, when it should have")
    end

  fun failure_case(h: TestHelper) =>
    let resolver = ALPNStandardProtocolResolver(["h2"], false)

    match resolver.resolve(["http/1.1"])
    | ALPNWarning => None
    else
      h.fail(
        "ALPNStandardProtocolResolver didn't return ALPNFailure, "
        + "when it should have")
    end

  fun match_cases(h: TestHelper) =>
    let resolver = ALPNStandardProtocolResolver(["h2"])

    match resolver.resolve(["dummy"; "h2"; "http/1.1"])
    | "h2" => None
    else
      h.fail("ALPNStandardProtocolResolver didn't return a matching protocol")
    end

class \nodoc\ iso _TestTCPSSLExpect is UnitTest
  """
  Test expecting framed data with TCP over SSL.
  """
  fun name(): String => "net/TCPSSL.expect"
  fun label(): String => "unreliable-osx"
  fun exclusion_group(): String => "network"

  fun ref apply(h: TestHelper) =>
    h.expect_action("client receive")
    h.expect_action("server receive")
    h.expect_action("expect received")

    (let ssl_client, let ssl_server) =
      try
        _TestSSLContext(h)?
      else
        h.fail("ssl stuff failed")
        return
      end

    _TestTCP(h)(
      SSLConnection(_TestTCPExpectNotify(h, false), consume ssl_client), SSLConnection(_TestTCPExpectNotify(h, true), consume ssl_server))

class \nodoc\ iso _TestTCPSSLWritev is UnitTest
  """
  Test writev (and sent/sentv notification).
  """
  fun name(): String => "net/TCPSSL.writev"
  fun exclusion_group(): String => "network"

  fun ref apply(h: TestHelper) =>
    h.expect_action("client connect")
    h.expect_action("server receive")

    (let ssl_client, let ssl_server) =
      try
        _TestSSLContext(h)?
      else
        h.fail("ssl stuff failed")
        return
      end

    _TestTCP(h)(
      SSLConnection(_TestTCPWritevNotifyClient(h), consume ssl_client), SSLConnection(_TestTCPWritevNotifyServer(h), consume ssl_server))

class \nodoc\ iso _TestTCPSSLMute is UnitTest
  """
  Test that the `mute` behavior stops us from reading incoming data. The
  test assumes that send/recv works correctly and that the absence of
  data received is because we muted the connection.

  Test works as follows:

  Once an incoming connection is established, we set mute on it and then
  verify that within a 2 second long test that received is not called on
  our notifier. A timeout is considering passing and received being called
  is grounds for a failure.
  """
  fun name(): String => "net/TCPSSLMute"
  fun exclusion_group(): String => "network"

  fun ref apply(h: TestHelper) =>
    h.expect_action("receiver accepted")
    h.expect_action("sender connected")
    h.expect_action("receiver muted")
    h.expect_action("receiver asks for data")
    h.expect_action("sender sent data")

    (let ssl_client, let ssl_server) =
      try
        _TestSSLContext(h)?
      else
        h.fail("ssl stuff failed")
        return
      end

    _TestTCP(h)(
      SSLConnection(_TestTCPMuteSendNotify(h), consume ssl_client),
      SSLConnection(_TestTCPMuteReceiveNotify(h), consume ssl_server))

  fun timed_out(h: TestHelper) =>
    h.complete(true)

class \nodoc\ iso _TestTCPSSLUnmute is UnitTest
  """
  Test that the `unmute` behavior will allow a connection to start reading
  incoming data again. The test assumes that `mute` works correctly and that
  after muting, `unmute` successfully reset the mute state rather than `mute`
  being broken and never actually muting the connection.

  Test works as follows:

  Once an incoming connection is established, we set mute on it, request
  that data be sent to us and then unmute the connection such that we should
  receive the return data.
  """
  fun name(): String => "net/TCPSSLUnmute"
  fun exclusion_group(): String => "network"

  fun ref apply(h: TestHelper) =>
    h.expect_action("receiver accepted")
    h.expect_action("sender connected")
    h.expect_action("receiver muted")
    h.expect_action("receiver asks for data")
    h.expect_action("receiver unmuted")
    h.expect_action("sender sent data")

    (let ssl_client, let ssl_server) =
      try
        _TestSSLContext(h)?
      else
        h.fail("ssl stuff failed")
        return
      end

    _TestTCP(h)(
      SSLConnection(_TestTCPMuteSendNotify(h), consume ssl_client),
      SSLConnection(_TestTCPUnmuteReceiveNotify(h), consume ssl_server))

class \nodoc\ iso _TestTCPSSLClientVerifyFalseWithHostname is UnitTest
  """
  Test that set_client_verify(false) disables hostname verification.
  The test certificate's SAN contains only "localhost" and 127.0.0.1, so
  with verification enabled, a client created with hostname
  "nomatch.example.com" would fail hostname verification. With
  set_client_verify(false), the connection should succeed.
  """
  fun name(): String => "net/TCPSSL.client_verify_false_with_hostname"
  fun exclusion_group(): String => "network"

  fun ref apply(h: TestHelper) =>
    h.expect_action("client connected")

    let auth = FileAuth(h.env.root)
    let sslctx =
      try
        recover val
          SSLContext
            .> set_authority(FilePath(auth, "assets/cert.pem"))?
            .> set_cert(
                FilePath(auth, "assets/cert.pem"),
                FilePath(auth, "assets/key.pem"))?
            .> set_client_verify(false)
            .> set_server_verify(false)
        end
      else
        h.fail("ssl context setup failed")
        return
      end

    let ssl_client =
      try
        sslctx.client("nomatch.example.com")?
      else
        h.fail("failed getting ssl client session")
        return
      end
    let ssl_server =
      try
        sslctx.server()?
      else
        h.fail("failed getting ssl server session")
        return
      end

    _TestTCP(h)(
      SSLConnection(
        _TestTCPSSLClientVerifyFalseNotify(h),
        consume ssl_client),
      SSLConnection(
        _TestTCPSSLClientVerifyFalseServerNotify(h),
        consume ssl_server))

class \nodoc\ _TestTCPSSLClientVerifyFalseNotify is TCPConnectionNotify
  let _h: TestHelper

  new iso create(h: TestHelper) =>
    _h = h

  fun ref connected(conn: TCPConnection ref) =>
    _h.complete_action("client connected")
    _h.complete(true)

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("client connect failed")

  fun ref auth_failed(conn: TCPConnection ref) =>
    _h.fail("hostname verification should have been skipped")

class \nodoc\ _TestTCPSSLClientVerifyFalseServerNotify is TCPConnectionNotify
  let _h: TestHelper

  new iso create(h: TestHelper) =>
    _h = h

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("server connect failed")

class \nodoc\ iso _TestTCPSSLPeerCertificateVerify is UnitTest
  """
  Full TLS handshake with the default `_client_verify = true` and a
  hostname matching the test certificate's SAN. Exercises the
  SSL_get1_peer_certificate / SSL_get_peer_certificate FFI binding in
  SSL._verify_hostname. The client notify's `connected` fires only when
  SSL state reaches SSLReady, which requires the peer certificate to be
  retrieved and matched successfully.

  The client and server use separate SSLContexts: the client context has
  no local certificate (only set_authority for trust), the server context
  has the cert. This separation distinguishes peer-cert retrieval from
  local-cert retrieval — a regression that called SSL_get_certificate
  (local cert) instead of SSL_get1_peer_certificate (peer cert) would
  return NULL on the client and fail verification.
  """
  fun name(): String => "net/TCPSSL.peer_certificate_verify"
  fun exclusion_group(): String => "network"

  fun ref apply(h: TestHelper) =>
    h.expect_action("client connected")

    let auth = FileAuth(h.env.root)
    let client_ctx =
      try
        recover val
          SSLContext
            .> set_authority(FilePath(auth, "assets/cert.pem"))?
        end
      else
        h.fail("client ssl context setup failed")
        return
      end
    // set_server_verify(false): the server does not verify the client,
    // so the client has no cert to present and no hostname for the
    // server to check.
    let server_ctx =
      try
        recover val
          SSLContext
            .> set_cert(
                FilePath(auth, "assets/cert.pem"),
                FilePath(auth, "assets/key.pem"))?
            .> set_server_verify(false)
        end
      else
        h.fail("server ssl context setup failed")
        return
      end

    let ssl_client =
      try
        client_ctx.client("localhost")?
      else
        h.fail("failed getting ssl client session")
        return
      end
    let ssl_server =
      try
        server_ctx.server()?
      else
        h.fail("failed getting ssl server session")
        return
      end

    _TestTCP(h)(
      SSLConnection(
        _TestTCPSSLPeerCertificateVerifyClientNotify(h),
        consume ssl_client),
      SSLConnection(
        _TestTCPSSLPeerCertificateVerifyServerNotify(h),
        consume ssl_server))

class \nodoc\ _TestTCPSSLPeerCertificateVerifyClientNotify is TCPConnectionNotify
  let _h: TestHelper

  new iso create(h: TestHelper) =>
    _h = h

  fun ref connected(conn: TCPConnection ref) =>
    _h.complete_action("client connected")
    _h.complete(true)

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("client connect failed")

  fun ref auth_failed(conn: TCPConnection ref) =>
    _h.fail("hostname verification should have succeeded")

class \nodoc\ _TestTCPSSLPeerCertificateVerifyServerNotify is TCPConnectionNotify
  let _h: TestHelper

  new iso create(h: TestHelper) =>
    _h = h

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("server connect failed")

class \nodoc\ iso _TestTCPSSLPeerCertificateHostnameMismatch is UnitTest
  """
  TLS handshake with the default `_client_verify = true` and a hostname that
  does not match the test certificate's SAN. The handshake itself succeeds,
  because the certificate is signed by an authority the client trusts.
  `X509.valid_for_host` then rejects the hostname, the SSL state becomes
  `SSLAuthFail`, and `SSLConnection` forwards `auth_failed` to the wrapped
  notify.

  The client and server use separate `SSLContext`s. The client's carries no
  certificate of its own, only the authority, so nothing but the peer's
  certificate can satisfy the check.

  Reaching `SSLAuthFail` does not on its own say that the hostname is what
  failed. A broken chain would land here too.
  """
  fun name(): String => "net/TCPSSL.peer_certificate_hostname_mismatch"
  fun exclusion_group(): String => "network"

  fun ref apply(h: TestHelper) =>
    h.expect_action("client auth failed")

    let auth = FileAuth(h.env.root)
    let client_ctx =
      try
        recover val
          SSLContext
            .> set_authority(FilePath(auth, "assets/cert.pem"))?
        end
      else
        h.fail("client ssl context setup failed")
        return
      end
    let server_ctx =
      try
        recover val
          SSLContext
            .> set_cert(
                FilePath(auth, "assets/cert.pem"),
                FilePath(auth, "assets/key.pem"))?
            .> set_server_verify(false)
        end
      else
        h.fail("server ssl context setup failed")
        return
      end

    let ssl_client =
      try
        client_ctx.client("nomatch.example.com")?
      else
        h.fail("failed getting ssl client session")
        return
      end
    let ssl_server =
      try
        server_ctx.server()?
      else
        h.fail("failed getting ssl server session")
        return
      end

    _TestTCP(h)(
      SSLConnection(
        _TestTCPSSLPeerCertificateHostnameMismatchClientNotify(h),
        consume ssl_client),
      SSLConnection(
        _TestTCPSSLPeerCertificateHostnameMismatchServerNotify(h),
        consume ssl_server))

class \nodoc\ _TestTCPSSLPeerCertificateHostnameMismatchClientNotify
  is TCPConnectionNotify
  let _h: TestHelper

  new iso create(h: TestHelper) =>
    _h = h

  fun ref connected(conn: TCPConnection ref) =>
    _h.fail("connected fired despite hostname mismatch")

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("client connect failed")

  fun ref auth_failed(conn: TCPConnection ref) =>
    _h.complete_action("client auth failed")
    _h.complete(true)

class \nodoc\ _TestTCPSSLPeerCertificateHostnameMismatchServerNotify
  is TCPConnectionNotify
  let _h: TestHelper

  new iso create(h: TestHelper) =>
    _h = h

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("server connect failed")

class \nodoc\ iso _TestTCPSSLThrottle is UnitTest
  """
  Test that when we experience backpressure when sending that the `throttled`
  method is called on our `TCPConnectionNotify` instance.

  We do this by starting up a server connection, muting it immediately and then
  sending data to it which should trigger a throttling to happen. We don't
  start sending data til after the receiver has muted itself and sent the
  sender data. This verifies that muting has been completed before any data is
  sent as part of testing throttling.

  This test assumes that muting functionality is working correctly.
  """
  fun name(): String => "net/TCPSSLThrottle"
  fun exclusion_group(): String => "network"

  fun ref apply(h: TestHelper) =>
    h.expect_action("receiver accepted")
    h.expect_action("sender connected")
    h.expect_action("receiver muted")
    h.expect_action("receiver asks for data")
    h.expect_action("sender sent data")
    h.expect_action("sender throttled")

    (let ssl_client, let ssl_server) =
      try
        _TestSSLContext(h)?
      else
        h.fail("ssl stuff failed")
        return
      end

    _TestTCP(h)(
      SSLConnection(_TestTCPThrottleSendNotify(h), consume ssl_client),
      SSLConnection(_TestTCPThrottleReceiveNotify(h), consume ssl_server))

class \nodoc\ iso _TestWindowsLoadRootCertificates is UnitTest
  """
  Test loading the Windows root certificates when `set_authority(None, None)`
  is called.
  """
  fun name(): String => "net/TCPSSLWindowsLoadRootCertificates"

  fun ref apply(h: TestHelper) =>
    try
      let auth = FileAuth(h.env.root)
      let ssl_ctx =
        recover val
          SSLContext
            .>set_authority(None, None)?
            .>set_cert(FilePath(auth, "assets/cert.pem"),
              FilePath(auth, "assets/key.pem"))?
            .>set_client_verify(false)
            .>set_server_verify(false)
        end

      let ssl_client = ssl_ctx.client()?
      let ssl_server = ssl_ctx.server()?

      _TestTCP(h)(
        SSLConnection(_TestTCPExpectNotify(h, false), consume ssl_client),
        SSLConnection(_TestTCPExpectNotify(h, true), consume ssl_server))
    else
      h.fail("set_authority failed")
    end

class \nodoc\ _TestTCPThrottleReceiveNotify is TCPConnectionNotify
  """
  Notifier to that mutes itself on startup. We then send data to it in order
  to trigger backpressure on the sender.
  """
  let _h: TestHelper

  new iso create(h: TestHelper) =>
    _h = h

  fun ref accepted(conn: TCPConnection ref) =>
    _h.complete_action("receiver accepted")
    conn.mute()
    _h.complete_action("receiver muted")
    conn.write("send me some data that i won't ever read")
    _h.complete_action("receiver asks for data")
    _h.dispose_when_done(conn)

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("receiver connect failed")

class \nodoc\ _TestTCPThrottleSendNotify is TCPConnectionNotify
  """
  Notifier that sends data back when it receives any. Used in conjunction with
  the mute receiver to verify that after muting, we don't get any data on
  to the `received` notifier on the muted connection. We only send in response
  to data from the receiver to make sure we don't end up failing due to race
  condition where the senders sends data on connect before the receiver has
  executed its mute statement.
  """
  let _h: TestHelper
  var _throttled_yet: Bool = false

  new iso create(h: TestHelper) =>
    _h = h

  fun ref connected(conn: TCPConnection ref) =>
    _h.complete_action("sender connected")

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("sender connect failed")

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] val,
    times: USize)
    : Bool
  =>
    conn.write("it's sad that you won't ever read this")
    _h.complete_action("sender sent data")
    true

  fun ref throttled(conn: TCPConnection ref) =>
    _throttled_yet = true
    _h.complete_action("sender throttled")
    _h.complete(true)

  fun ref sent(conn: TCPConnection ref, data: ByteSeq): ByteSeq =>
    if not _throttled_yet then
      conn.write("this is more data that you won't ever read" * 10000)
    end
    data

class \nodoc\ _TestTCPMuteReceiveNotify is TCPConnectionNotify
  """
  Notifier to fail a test if we receive data after muting the connection.
  """
  let _h: TestHelper

  new iso create(h: TestHelper) =>
    _h = h

  fun ref accepted(conn: TCPConnection ref) =>
    _h.complete_action("receiver accepted")
    conn.mute()
    _h.complete_action("receiver muted")
    conn.write("send me some data that i won't ever read")
    _h.complete_action("receiver asks for data")
    _h.dispose_when_done(conn)

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] val,
    times: USize)
    : Bool
  =>
    _h.complete(false)
    true

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("receiver connect failed")


class \nodoc\ _TestTCPMuteSendNotify is TCPConnectionNotify
  """
  Notifier that sends data back when it receives any. Used in conjunction with
  the mute receiver to verify that after muting, we don't get any data on
  to the `received` notifier on the muted connection. We only send in response
  to data from the receiver to make sure we don't end up failing due to race
  condition where the senders sends data on connect before the receiver has
  executed its mute statement.
  """
  let _h: TestHelper

  new iso create(h: TestHelper) =>
    _h = h

  fun ref connected(conn: TCPConnection ref) =>
    _h.complete_action("sender connected")

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("sender connect failed")

   fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] val,
    times: USize)
    : Bool
   =>
     conn.write("it's sad that you won't ever read this")
     _h.complete_action("sender sent data")
     true

class \nodoc\ _TestTCPExpectNotify is TCPConnectionNotify
  let _h: TestHelper
  let _server: Bool
  var _expect: USize = 4
  var _frame: Bool = true

  new iso create(h: TestHelper, server: Bool) =>
    _server = server
    _h = h

  fun ref accepted(conn: TCPConnection ref) =>
    conn.set_nodelay(true)
    try
      conn.expect(_expect)?
      _send(conn, "hi there")
    else
      _h.fail("expect threw an error")
    end

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("client connect failed")

  fun ref connected(conn: TCPConnection ref) =>
    _h.complete_action("client connect")
    conn.set_nodelay(true)
    try
      conn.expect(_expect)?
    else
      _h.fail("expect threw an error")
    end

  fun ref expect(conn: TCPConnection ref, qty: USize): USize =>
    _h.complete_action("expect received")
    qty

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] val,
    times: USize)
    : Bool
  =>
    if _frame then
      _frame = false
      _expect = 0

      for i in data.values() do
        _expect = (_expect << 8) + i.usize()
      end
    else
      _h.assert_eq[USize](_expect, data.size())

      if _server then
        _h.complete_action("server receive")
        _h.assert_eq[String](String.from_array(data), "goodbye")
      else
        _h.complete_action("client receive")
        _h.assert_eq[String](String.from_array(data), "hi there")
        _send(conn, "goodbye")
      end

      _frame = true
      _expect = 4
    end

    try
      conn.expect(_expect)?
    else
      _h.fail("expect threw an error")
    end
    true

  fun ref _send(conn: TCPConnection ref, data: String) =>
    let len = data.size()

    var buf = recover Array[U8] end
    buf.push((len >> 24).u8())
    buf.push((len >> 16).u8())
    conn.write(consume buf)

    buf = recover Array[U8] end
    buf.push((len >> 8).u8())
    buf.push((len >> 0).u8())
    buf.append(data)
    conn.write(consume buf)

class \nodoc\ _TestTCPWritevNotifyClient is TCPConnectionNotify
  let _h: TestHelper

  new iso create(h: TestHelper) =>
    _h = h

  fun ref sentv(conn: TCPConnection ref, data: ByteSeqIter): ByteSeqIter =>
    recover
      Array[ByteSeq] .> concat(data.values()) .> push(" (from client)")
    end

  fun ref connected(conn: TCPConnection ref) =>
    _h.complete_action("client connect")
    conn.writev(recover ["hello"; ", hello"] end)

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("client connect failed")

class \nodoc\ _TestTCPWritevNotifyServer is TCPConnectionNotify
  let _h: TestHelper
  var _buffer: String iso = recover iso String end

  new iso create(h: TestHelper) =>
    _h = h

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] iso,
    times: USize)
    : Bool
  =>
    _buffer.append(consume data)

    let expected = "hello, hello (from client)"

    if _buffer.size() >= expected.size() then
      let buffer: String = _buffer = recover iso String end
      _h.assert_eq[String](expected, consume buffer)
      _h.complete_action("server receive")
    end
    true

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("sender connect failed")

class \nodoc\ _TestTCP is TCPListenNotify
  """
  Run a typical TCP test consisting of a single TCPListener that accepts a
  single TCPConnection as a client, using a dynamic available listen port.
  """
  let _h: TestHelper
  var _client_conn_notify: (TCPConnectionNotify iso | None) = None
  var _server_conn_notify: (TCPConnectionNotify iso | None) = None

  new iso create(h: TestHelper) =>
    _h = h

  fun iso apply(c: TCPConnectionNotify iso, s: TCPConnectionNotify iso) =>
    _client_conn_notify = consume c
    _server_conn_notify = consume s

    let h = _h
    h.expect_action("server create")
    h.expect_action("server listen")
    h.expect_action("client create")
    h.expect_action("server accept")

    let auth = TCPListenAuth(h.env.root)
    h.dispose_when_done(TCPListener(auth, consume this))
    h.complete_action("server create")

    h.long_test(2_000_000_000)

  fun ref not_listening(listen: TCPListener ref) =>
    _h.fail_action("server listen")

  fun ref listening(listen: TCPListener ref) =>
    _h.complete_action("server listen")

    try
      let auth = TCPConnectAuth(_h.env.root)
      let notify = (_client_conn_notify = None) as TCPConnectionNotify iso^
      (let host, let port) = listen.local_address().name()?
      _h.dispose_when_done(TCPConnection(auth, consume notify, host, port))
      _h.complete_action("client create")
    else
      _h.fail_action("client create")
    end

  fun ref connected(listen: TCPListener ref): TCPConnectionNotify iso^ ? =>
    try
      let notify = (_server_conn_notify = None) as TCPConnectionNotify iso^
      _h.complete_action("server accept")
      consume notify
    else
      _h.fail_action("server accept")
      error
    end

class \nodoc\ _TestTCPUnmuteReceiveNotify is TCPConnectionNotify
  """
  Notifier to test that after muting and unmuting a connection, we get data
  """
  let _h: TestHelper

  new iso create(h: TestHelper) =>
    _h = h

  fun ref accepted(conn: TCPConnection ref) =>
    _h.complete_action("receiver accepted")
    conn.mute()
    _h.complete_action("receiver muted")
    conn.write("send me some data that i won't ever read")
    _h.complete_action("receiver asks for data")
    conn.unmute()
    _h.complete_action("receiver unmuted")

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] val,
    times: USize)
    : Bool
  =>
    _h.complete(true)
    true

  fun ref connect_failed(conn: TCPConnection ref) =>
    _h.fail_action("receiver connect failed")

primitive \nodoc\ _TestSSLContext
  fun val apply(h: TestHelper): (SSL iso^, SSL iso^) ? =>
    let sslctx =
      try
        let auth = FileAuth(h.env.root)
        recover val
          SSLContext
            .> set_authority(FilePath(auth, "assets/cert.pem"))?
            .> set_cert(
                FilePath(auth, "assets/cert.pem"),
                FilePath(auth, "assets/key.pem"))?
            .> set_client_verify(false)
            .> set_server_verify(false)
        end
      else
        h.fail("set_cert failed")
        error
      end

    let ssl_client =
      try
        sslctx.client()?
      else
        h.fail("failed getting ssl client session")
        error
      end
    let ssl_server =
      try
        sslctx.server()?
      else
        h.fail("failed getting ssl server session")
        error
      end

    (consume ssl_client, consume ssl_server)

primitive \nodoc\ _TestSSLTransfer
  fun val apply(sender: SSL, receiver: SSL) ? =>
    """
    Hand every encrypted byte the sender has ready over to the receiver, the
    way a transport would.
    """
    while sender.can_send() do
      receiver.receive(sender.send()?)
    end

primitive \nodoc\ _TestSSLSessionPair
  fun val apply(h: TestHelper): (SSL, SSL) ? =>
    """
    A handshaken client and server session from the standard test context,
    with no transport between them.
    """
    (let client, let server) = fresh(h)?
    _handshake(h, client, server)?
    (client, server)

  fun val fresh(h: TestHelper): (SSL, SSL) ? =>
    """
    A client and a server session from the standard test context, before any
    handshake. Both are in `SSLHandshake`.
    """
    (let client_session, let server_session) = _TestSSLContext(h)?
    let client: SSL = consume client_session
    let server: SSL = consume server_session
    (client, server)

  fun val from_context(h: TestHelper, sslctx: SSLContext val): (SSL, SSL) ? =>
    """
    A handshaken client and server session from `sslctx`, with no transport
    between them.
    """
    let client: SSL =
      try
        sslctx.client()?
      else
        h.fail("failed getting ssl client session")
        error
      end
    let server: SSL =
      try
        sslctx.server()?
      else
        h.fail("failed getting ssl server session")
        error
      end
    _handshake(h, client, server)?
    (client, server)

  fun val _handshake(h: TestHelper, client: SSL, server: SSL) ? =>
    """
    Drive a handshake to completion by handing each side's outgoing bytes
    straight to the other. Reports the reason and raises an error if the
    handshake does not finish.
    """
    // How many rounds a handshake takes depends on the TLS version and the
    // backend, so this is a backstop against a session that never settles,
    // not a count anything should rely on.
    let max_rounds: USize = 20
    var rounds: USize = 0

    while
      (client.state() is SSLHandshake) or (server.state() is SSLHandshake)
    do
      if rounds == max_rounds then
        h.fail(
          "in memory SSL handshake did not finish in "
            + max_rounds.string() + " rounds")
        error
      end
      rounds = rounds + 1

      _TestSSLTransfer(client, server)?
      _TestSSLTransfer(server, client)?
    end

    if (client.state() isnt SSLReady) or (server.state() isnt SSLReady) then
      h.fail("in memory SSL handshake did not reach SSLReady")
      error
    end

class \nodoc\ iso _TestSSLHandshakeInMemory is UnitTest
  """
  Two SSL sessions can complete a handshake with no transport between them by
  handing each side's outgoing bytes straight to the other, and application
  data written by one can be read by the other.

  The `after_dispose` tests all start from a handshaken pair. This test
  verifies that the pair really handshakes and really moves data, so when one
  of those tests fails, the session under test is at fault and not the
  harness.
  """
  fun name(): String => "net/ssl/SSL/handshake_in_memory"

  fun apply(h: TestHelper) =>
    (let client, let server) =
      try
        _TestSSLSessionPair(h)?
      else
        h.fail("could not establish an SSL session pair")
        return
      end

    h.assert_true(client.state() is SSLReady, "client is not SSLReady")
    h.assert_true(server.state() is SSLReady, "server is not SSLReady")

    try
      client.write("hello")?
      _TestSSLTransfer(client, server)?
    else
      h.fail("client could not send application data")
      client.dispose()
      server.dispose()
      return
    end

    match server.read()
    | let data: Array[U8] iso =>
      h.assert_eq[String]("hello", String.from_array(consume data))
    | None =>
      h.fail("server read no application data")
    end

    client.dispose()
    server.dispose()

class \nodoc\ iso _TestSSLDisposeBeforeHandshake is UnitTest
  """
  A session disposed before its handshake finishes is inert too, and `state`
  reports `SSLDisposed` rather than the `SSLHandshake` it was in. This is the
  case from issue #66: a fresh client session, disposed, then read.

  A fresh client session has a ClientHello waiting to go out, so `can_send`
  returning `false` after the dispose is the disposed check and not an empty
  BIO.
  """
  fun name(): String => "net/ssl/SSL.dispose/before_handshake"

  fun apply(h: TestHelper) =>
    (let client, let server) =
      try
        _TestSSLSessionPair.fresh(h)?
      else
        h.fail("could not create an SSL session pair")
        return
      end

    h.assert_true(
      client.state() is SSLHandshake,
      "a fresh client session should be in SSLHandshake")
    h.assert_true(
      client.can_send(),
      "a fresh client session should have a ClientHello to send")

    client.dispose()

    h.assert_true(
      client.state() is SSLDisposed,
      "dispose() from SSLHandshake should leave the session SSLDisposed")
    h.assert_true(
      client.read() is None,
      "read() on a disposed session should return None")
    h.assert_false(
      client.can_send(),
      "can_send() on a disposed session should return false")

    client.receive("bytes that will never be decrypted")

    try
      client.send()?
      h.fail("send() on a disposed session should raise an error")
    end

    server.dispose()

class \nodoc\ iso _TestSSLDisposeTwice is UnitTest
  """
  Disposing a session twice does not free the session or its BIOs twice, and
  the session is still inert afterwards.
  """
  fun name(): String => "net/ssl/SSL.dispose/twice"

  fun apply(h: TestHelper) =>
    (let client, let server) =
      try
        _TestSSLSessionPair(h)?
      else
        h.fail("could not establish an SSL session pair")
        return
      end

    client.dispose()
    client.dispose()

    h.assert_true(
      client.read() is None,
      "read() on a disposed session should return None")
    h.assert_false(
      client.can_send(),
      "can_send() on a disposed session should return false")

    server.dispose()

class \nodoc\ iso _TestSSLReadAfterDispose is UnitTest
  """
  `read` on a disposed session returns `None` instead of passing a null
  `SSL*` to `SSL_pending`.
  """
  fun name(): String => "net/ssl/SSL.read/after_dispose"

  fun apply(h: TestHelper) =>
    (let client, let server) =
      try
        _TestSSLSessionPair(h)?
      else
        h.fail("could not establish an SSL session pair")
        return
      end

    client.dispose()

    h.assert_true(
      client.read() is None,
      "read() on a disposed session should return None")
    h.assert_true(
      client.read(4) is None,
      "read(4) on a disposed session should return None")

    server.dispose()

class \nodoc\ iso _TestSSLReadAfterDisposeWithBufferedFrame is UnitTest
  """
  A session holding decrypted bytes from an incomplete `expect` frame returns
  `None` from `read` once it is disposed, rather than handing those bytes
  back.

  This is the one post-dispose read that did not crash before the fix. With
  at least `expect` bytes already buffered, `read` returns them without
  touching the freed session.
  """
  fun name(): String => "net/ssl/SSL.read/after_dispose_with_buffered_frame"

  fun apply(h: TestHelper) =>
    (let client, let server) =
      try
        _TestSSLSessionPair(h)?
      else
        h.fail("could not establish an SSL session pair")
        return
      end

    try
      client.write("ab")?
      _TestSSLTransfer(client, server)?
    else
      h.fail("client could not send application data")
      client.dispose()
      server.dispose()
      return
    end

    h.assert_true(
      server.read(4) is None,
      "two bytes should not satisfy read(4)")

    server.dispose()

    h.assert_true(
      server.read(2) is None,
      "read(2) on a disposed session should return None, even with two bytes "
        + "already buffered")

    client.dispose()

class \nodoc\ iso _TestSSLReceiveAfterDispose is UnitTest
  """
  `receive` on a disposed session does nothing instead of writing into a freed
  BIO. There is nothing to observe afterwards beyond the session still reading
  as empty.
  """
  fun name(): String => "net/ssl/SSL.receive/after_dispose"

  fun apply(h: TestHelper) =>
    (let client, let server) =
      try
        _TestSSLSessionPair(h)?
      else
        h.fail("could not establish an SSL session pair")
        return
      end

    server.dispose()
    server.receive("bytes that will never be decrypted")

    h.assert_true(
      server.read() is None,
      "a disposed session has nothing to read")

    client.dispose()

class \nodoc\ iso _TestSSLCanSendAfterDispose is UnitTest
  """
  `can_send` on a disposed session returns `false` instead of reading a freed
  BIO.

  The session has encrypted bytes waiting when it is disposed, so a `false`
  here is the disposed check and not an empty BIO. A live session with nothing
  to send returns `false` too.
  """
  fun name(): String => "net/ssl/SSL.can_send/after_dispose"

  fun apply(h: TestHelper) =>
    (let client, let server) =
      try
        _TestSSLSessionPair(h)?
      else
        h.fail("could not establish an SSL session pair")
        return
      end

    try
      client.write("data")?
    else
      h.fail("client could not write application data")
      client.dispose()
      server.dispose()
      return
    end

    h.assert_true(
      client.can_send(),
      "a session that has just written should have bytes to send")

    client.dispose()

    h.assert_false(
      client.can_send(),
      "can_send() on a disposed session should return false")

    server.dispose()

class \nodoc\ iso _TestSSLSendAfterDispose is UnitTest
  """
  `send` on a disposed session raises an error instead of reading a freed BIO.

  The session has encrypted bytes waiting when it is disposed, so the error
  here is the disposed check and not the empty BIO check.
  """
  fun name(): String => "net/ssl/SSL.send/after_dispose"

  fun apply(h: TestHelper) =>
    (let client, let server) =
      try
        _TestSSLSessionPair(h)?
      else
        h.fail("could not establish an SSL session pair")
        return
      end

    try
      client.write("data")?
    else
      h.fail("client could not write application data")
      client.dispose()
      server.dispose()
      return
    end

    h.assert_true(
      client.can_send(),
      "a session that has just written should have bytes to send")

    client.dispose()

    try
      client.send()?
      h.fail("send() on a disposed session should raise an error")
    end

    server.dispose()

class \nodoc\ iso _TestSSLWriteAfterDispose is UnitTest
  """
  `write` on a disposed session does nothing and does not raise. Being disposed
  is not an error, and `write`'s only error means the handshake is not
  complete, which is not what happened here.

  The session reaches `SSLReady` first, so the dispose is the only reason
  `write` could have to stop, and `state` reports `SSLDisposed` afterwards.
  """
  fun name(): String => "net/ssl/SSL.write/after_dispose"

  fun apply(h: TestHelper) =>
    (let client, let server) =
      try
        _TestSSLSessionPair(h)?
      else
        h.fail("could not establish an SSL session pair")
        return
      end

    h.assert_true(
      client.state() is SSLReady,
      "client should be SSLReady after the handshake")

    client.dispose()

    h.assert_true(
      client.state() is SSLDisposed,
      "dispose() from SSLReady should leave the session SSLDisposed")

    try
      client.write("data")?
    else
      h.fail("write() on a disposed session should not raise an error")
    end

    h.assert_false(
      client.can_send(),
      "write() on a disposed session should not queue anything to send")

    server.dispose()

class \nodoc\ iso _TestSSLALPNSelectedAfterDispose is UnitTest
  """
  `alpn_selected` on a disposed session returns `None` rather than the
  protocol the session negotiated. The session negotiates one before it is
  disposed, so the `None` afterwards is the disposed check and not the absence
  of ALPN.

  This test passes with and without the disposed check on OpenSSL, whose
  `SSL_get0_alpn_selected` checks its own `SSL*` for null. We do not rely on
  that, and LibreSSL has not been checked, so the disposed check is what keeps
  the return value from depending on the backend.
  """
  fun name(): String => "net/ssl/SSL.alpn_selected/after_dispose"

  fun apply(h: TestHelper) =>
    let sslctx =
      try
        _TestALPNContext(h, ALPNStandardProtocolResolver(["h2"]))?
      else
        return
      end

    (let client, let server) =
      try
        _TestSSLSessionPair.from_context(h, sslctx)?
      else
        h.fail("could not establish an SSL session pair")
        return
      end

    match client.alpn_selected()
    | let protocol: ALPNProtocolName =>
      h.assert_eq[String]("h2", protocol)
    | None =>
      h.fail("the client did not negotiate an ALPN protocol")
    end

    client.dispose()

    h.assert_true(
      client.alpn_selected() is None,
      "alpn_selected() on a disposed session should return None")

    server.dispose()

class \nodoc\ iso _TestSSLContextDisposeTwice is UnitTest
  """
  Disposing a context twice does not free it twice, and the context is still
  inert afterwards.

  `dispose` nulling `_ctx` is what makes the second call safe, and losing that
  is what this test would catch. The `_ctx.is_null()` check in `dispose` is belt
  and braces, because `SSL_CTX_free` ignores a null pointer.
  """
  fun name(): String => "net/ssl/SSLContext.dispose/twice"

  fun apply(h: TestHelper) =>
    let ctx = SSLContext

    ctx.dispose()
    ctx.dispose()

    // A live context accepts this protocol list, so a `false` here is the
    // context still being disposed and not a list it rejected.
    h.assert_false(
      ctx.alpn_set_client_protocols(["h2"]),
      "a disposed context should still be inert after a second dispose()")

class \nodoc\ iso _TestSSLContextALPNSetResolverAfterDispose is UnitTest
  """
  `alpn_set_resolver` on a disposed context returns `false` rather than passing
  a null `SSL_CTX*` to `SSL_CTX_set_alpn_select_cb`, which dereferences it on
  every backend.

  The live context returns `true`, so the `false` afterwards is the disposed
  check and not a resolver the context rejected.
  """
  fun name(): String => "net/ssl/SSLContext.alpn_set_resolver/after_dispose"

  fun apply(h: TestHelper) =>
    let resolver = ALPNStandardProtocolResolver(["h2"])
    let ctx = SSLContext

    h.assert_true(
      ctx.alpn_set_resolver(resolver),
      "alpn_set_resolver() on a live context should return true")

    ctx.dispose()

    h.assert_false(
      ctx.alpn_set_resolver(resolver),
      "alpn_set_resolver() on a disposed context should return false")

class \nodoc\ val _TestALPNFixedResolver is ALPNProtocolResolver
  """
  Resolves every advertisement to one name, whatever the client advertised.
  """
  let _protocol: String

  new val create(protocol: String) =>
    _protocol = protocol

  fun box resolve(advertised: Array[ALPNProtocolName] val): ALPNMatchResult =>
    _protocol

class \nodoc\ iso _TestSSLContextALPNFallbackToClientProtocol is UnitTest
  """
  A resolver that falls back to the client's first advertised protocol
  negotiates it.

  `ALPNStandardProtocolResolver` takes that name from the array the select
  callback built out of a copy of the wire buffer, not from its own `supported`
  list. It is the name the callback has no lifetime for, and the one the fix has
  to point back into the buffer OpenSSL passed in.

  The resolver's `supported` list shares nothing with what the client
  advertises, so the fallback is the only way it can select anything.

  The pointer moving is not observable from here. Every supported backend copies
  the bytes out of `*out` inside the callback's own C frame, so the pointer the
  callback handed over before this change was still live when it was read. What
  this drives is the path, and what it pins is that the fallback still negotiates
  once the pointer points into the client's buffer.
  """
  fun name(): String =>
    "net/ssl/SSLContext.alpn_set_resolver/fallback_to_client_protocol"

  fun apply(h: TestHelper) ? =>
    let ctx = _TestALPNContext(h, ALPNStandardProtocolResolver(["spdy/1"]))?
    (let client, let server) = _TestSSLSessionPair.from_context(h, ctx)?

    match client.alpn_selected()
    | let protocol: ALPNProtocolName =>
      h.assert_eq[String](
        "h2", protocol, "the client's own protocol should be selected")
    | None =>
      h.fail("the client did not negotiate an ALPN protocol")
    end

    client.dispose()
    server.dispose()

class \nodoc\ iso _TestSSLContextALPNUnadvertisedProtocolFails is UnitTest
  """
  A server whose resolver returns a protocol the client did not advertise stops
  handshaking on the client's first flight.

  The callback may only hand OpenSSL a pointer into the buffer the client sent.
  A name that is nowhere in that buffer has no such pointer, and a server that
  selects a protocol the client never offered is wrong to begin with.

  The assertion is on the server, and after a single transfer. An OpenSSL client
  refuses an unadvertised protocol on its own, a round or two later, so a test
  that waited for the whole handshake to fail would pass whether or not the
  server refused. It would be measuring the client.
  """
  fun name(): String =>
    "net/ssl/SSLContext.alpn_set_resolver/unadvertised_protocol_fails"

  fun apply(h: TestHelper) ? =>
    let ctx = _TestALPNContext(h, _TestALPNFixedResolver("spdy/1"))?
    let client: SSL = ctx.client()?
    let server: SSL = ctx.server()?

    // The client's opening flight carries the protocols it advertises. Handing
    // it to the server is what runs the resolver.
    _TestSSLTransfer(client, server)?

    h.assert_false(
      server.state() is SSLHandshake,
      "the server should refuse a protocol the client did not advertise")

    client.dispose()
    server.dispose()

class \nodoc\ val _TestALPNTrackedResolver is ALPNProtocolResolver
  """
  Resolves every advertisement to "h2" and reports its own collection by writing
  a byte through `_collected`, a raw pointer into an array a live
  `_TestALPNResolverTracker` holds.
  """
  let _collected: Pointer[U8] tag

  new val create(collected: Pointer[U8] tag) =>
    _collected = collected

  fun box resolve(advertised: Array[ALPNProtocolName] val): ALPNMatchResult =>
    "h2"

  fun _final() =>
    @memset(_collected, I32(1), USize(1))

class \nodoc\ _TestALPNResolverTracker
  """
  Reports whether the resolver it hands out has been garbage collected.
  """
  embed _flag: Array[U8] = Array[U8].init(0, 1)

  fun box resolver(): _TestALPNTrackedResolver =>
    """
    A resolver that reports its collection to this tracker. The tracker does not
    hold a reference to it: whether something else does is what the tests
    measure.
    """
    _TestALPNTrackedResolver(_flag.cpointer())

  fun box collected(): Bool =>
    // A one element array cannot fail to index. If it somehow did, treat it as
    // collected rather than as the resolver still being alive.
    try _flag(0)? != 0 else true end

primitive \nodoc\ _TestALPNContext
  fun apply(h: TestHelper, resolver: ALPNProtocolResolver val): SSLContext val ?
  =>
    """
    A context that both advertises and resolves the "h2" protocol, so a session
    pair made from it negotiates ALPN.
    """
    let auth = FileAuth(h.env.root)
    try
      recover val
        SSLContext
          .> set_authority(FilePath(auth, "assets/cert.pem"))?
          .> set_cert(
              FilePath(auth, "assets/cert.pem"),
              FilePath(auth, "assets/key.pem"))?
          .> set_client_verify(false)
          .> set_server_verify(false)
          .> alpn_set_client_protocols(["h2"])
          .> alpn_set_resolver(resolver)
      end
    else
      h.fail("ssl context setup failed")
      error
    end

actor \nodoc\ _TestALPNResolverContextRooting
  """
  Pony collects between behaviors, so the context is built in one behavior and
  the resolver checked in the next.
  """
  let _h: TestHelper
  embed _tracker: _TestALPNResolverTracker = _TestALPNResolverTracker
  var _ctx: (SSLContext val | None) = None

  new create(h: TestHelper) =>
    _h = h

  be run() =>
    // `resolver` is a local, so once this behavior returns the context is the
    // only thing that can be keeping it alive.
    let resolver = _tracker.resolver()

    try
      _ctx = _TestALPNContext(_h, resolver)?
    else
      _h.complete(false)
      return
    end

    @pony_triggergc(@pony_ctx())
    _check()

  be _check() =>
    if _tracker.collected() then
      _h.fail("the context did not keep the resolver alive")
      _h.complete(false)
      return
    end

    let ctx =
      match _ctx
      | let c: SSLContext val => c
      | None =>
        _h.fail("the context was never created")
        _h.complete(false)
        return
      end

    (let client, let server) =
      try
        _TestSSLSessionPair.from_context(_h, ctx)?
      else
        _h.complete(false)
        return
      end

    match client.alpn_selected()
    | let protocol: ALPNProtocolName =>
      _h.assert_eq[String]("h2", protocol)
    | None =>
      _h.fail("the client did not negotiate an ALPN protocol")
    end

    client.dispose()
    server.dispose()
    _h.complete(true)

actor \nodoc\ _TestALPNResolverSessionRooting
  """
  Pony collects between behaviors, so the sessions are made in one behavior and
  the resolver checked in the next.
  """
  let _h: TestHelper
  embed _tracker: _TestALPNResolverTracker = _TestALPNResolverTracker
  var _client: (SSL | None) = None
  var _server: (SSL | None) = None

  new create(h: TestHelper) =>
    _h = h

  be run() =>
    // The resolver and the context are locals, so once this behavior returns
    // the sessions are the only thing keeping the resolver alive, through the
    // context they hold.
    let resolver = _tracker.resolver()

    try
      let ctx = _TestALPNContext(_h, resolver)?
      _client = ctx.client()?
      _server = ctx.server()?
    else
      _h.fail("could not create an SSL session pair")
      _h.complete(false)
      return
    end

    @pony_triggergc(@pony_ctx())
    _check()

  be _check() =>
    (let client, let server) =
      try
        (_client as SSL, _server as SSL)
      else
        _h.fail("the sessions were never created")
        _h.complete(false)
        return
      end

    if _tracker.collected() then
      _h.fail("the sessions did not keep the resolver alive")
      client.dispose()
      server.dispose()
      _h.complete(false)
      return
    end

    try
      _TestSSLSessionPair._handshake(_h, client, server)?
    else
      client.dispose()
      server.dispose()
      _h.complete(false)
      return
    end

    match client.alpn_selected()
    | let protocol: ALPNProtocolName =>
      _h.assert_eq[String]("h2", protocol)
    | None =>
      _h.fail("the client did not negotiate an ALPN protocol")
    end

    client.dispose()
    server.dispose()
    _h.complete(true)

class \nodoc\ iso _TestSSLContextALPNResolverRootedByContext is UnitTest
  """
  A context keeps its ALPN resolver alive.

  `alpn_set_resolver` hands OpenSSL a raw pointer to the resolver, and the Pony
  garbage collector cannot see it. Without a reference on the Pony side, a
  collection frees the resolver while OpenSSL still calls it on every later
  server-side handshake.

  The resolver reports its own collection from `_final`. This test drops every
  reference to it but the context's, triggers a collection, and then negotiates
  ALPN through the resolver the context held.

  The negotiation runs only once the resolver is known to be alive. A resolver
  that was collected would be a use after free, and a crash tells nobody which
  test caused it.
  """
  fun name(): String =>
    "net/ssl/SSLContext.alpn_set_resolver/resolver_rooted_by_context"

  fun apply(h: TestHelper) =>
    h.long_test(2_000_000_000)
    _TestALPNResolverContextRooting(h).run()

class \nodoc\ iso _TestSSLContextALPNResolverRootedBySession is UnitTest
  """
  A session keeps the ALPN resolver alive after the context that made it is
  dropped.

  `SSL_new` takes a reference on the `SSL_CTX`, so the `SSL_CTX` outlives an
  `SSLContext` the caller drops while a session is still alive, and the ALPN
  select callback OpenSSL reads out of it still points at the resolver. A
  session holds the `SSLContext`, which holds the resolver, so both live as long
  as the session does. This test keeps only the sessions and drops the context
  the way a caller would.

  Carries the same caveats as
  `net/ssl/SSLContext.alpn_set_resolver/resolver_rooted_by_context`.
  """
  fun name(): String =>
    "net/ssl/SSLContext.alpn_set_resolver/resolver_rooted_by_session"

  fun apply(h: TestHelper) =>
    h.long_test(2_000_000_000)
    _TestALPNResolverSessionRooting(h).run()

actor \nodoc\ _TestALPNResolverUnreferenced
  """
  Pony collects between behaviors, so the context is built in one behavior and
  the resolver checked in the next.
  """
  let _h: TestHelper
  embed _tracker: _TestALPNResolverTracker = _TestALPNResolverTracker

  new create(h: TestHelper) =>
    _h = h

  be run() =>
    // The resolver, the context, and the session are all locals. Once this
    // behavior returns nothing roots the resolver.
    let resolver = _tracker.resolver()

    try
      _TestALPNContext(_h, resolver)?.client()?.dispose()
    else
      _h.fail("could not create an SSL session")
      _h.complete(false)
      return
    end

    @pony_triggergc(@pony_ctx())
    _check()

  be _check() =>
    _h.assert_true(
      _tracker.collected(),
      "a resolver nothing holds should be collected")
    _h.complete(true)

class \nodoc\ iso _TestSSLContextALPNResolverUnreferenced is UnitTest
  """
  A resolver that nothing holds is collected.

  This is the positive control for
  `net/ssl/SSLContext.alpn_set_resolver/resolver_rooted_by_context` and
  `..._by_session`, which pass by the resolver *not* being collected. It builds
  the same resolver, keeps neither the context nor a session, and shows the
  collection happens. Without it, a change that stopped collections altogether
  would leave both rooting tests passing for the wrong reason.
  """
  fun name(): String =>
    "net/ssl/SSLContext.alpn_set_resolver/resolver_collected_when_unreferenced"

  fun apply(h: TestHelper) =>
    h.long_test(2_000_000_000)
    _TestALPNResolverUnreferenced(h).run()

class \nodoc\ iso _TestSSLContextALPNSetClientProtocolsAfterDispose is UnitTest
  """
  `alpn_set_client_protocols` on a disposed context returns `false` rather than
  passing a null `SSL_CTX*` to `SSL_CTX_set_alpn_protos`, which dereferences it
  on every backend.

  The protocol list is valid and the live context accepts it, so the `false`
  afterwards is the disposed check and not the encoding failure that also
  returns `false`.
  """
  fun name(): String =>
    "net/ssl/SSLContext.alpn_set_client_protocols/after_dispose"

  fun apply(h: TestHelper) =>
    let ctx = SSLContext

    h.assert_true(
      ctx.alpn_set_client_protocols(["h2"]),
      "alpn_set_client_protocols() on a live context should return true")

    ctx.dispose()

    h.assert_false(
      ctx.alpn_set_client_protocols(["h2"]),
      "alpn_set_client_protocols() on a disposed context should return false")

class \nodoc\ iso _TestSSLContextSetMinProtoVersionAfterDispose is UnitTest
  """
  `set_min_proto_version` on a disposed context raises an error rather than
  passing a null `SSL_CTX*` to `SSL_CTX_ctrl`.

  This test passes with and without the disposed check on OpenSSL, whose
  `SSL_CTX_ctrl` returns 0 for a null context, which this method already turns
  into an error. LibreSSL's `SSL_CTX_ctrl` dereferences the context instead, so
  LibreSSL is where the check keeps this from being a crash.
  """
  fun name(): String => "net/ssl/SSLContext.set_min_proto_version/after_dispose"

  fun apply(h: TestHelper) =>
    let ctx = SSLContext

    try
      ctx.set_min_proto_version(Tls1u2Version())?
    else
      h.fail("set_min_proto_version() on a live context should not raise")
    end

    ctx.dispose()

    try
      ctx.set_min_proto_version(Tls1u2Version())?
      h.fail("set_min_proto_version() on a disposed context should raise")
    end

class \nodoc\ iso _TestSSLContextSetMaxProtoVersionAfterDispose is UnitTest
  """
  `set_max_proto_version` on a disposed context raises an error rather than
  passing a null `SSL_CTX*` to `SSL_CTX_ctrl`.

  Carries the same caveat as
  `net/ssl/SSLContext.set_min_proto_version/after_dispose`: only LibreSSL
  crashes without the check.
  """
  fun name(): String => "net/ssl/SSLContext.set_max_proto_version/after_dispose"

  fun apply(h: TestHelper) =>
    let ctx = SSLContext

    try
      ctx.set_max_proto_version(Tls1u3Version())?
    else
      h.fail("set_max_proto_version() on a live context should not raise")
    end

    ctx.dispose()

    try
      ctx.set_max_proto_version(Tls1u3Version())?
      h.fail("set_max_proto_version() on a disposed context should raise")
    end

class \nodoc\ iso _TestSSLContextGetMinProtoVersionAfterDispose is UnitTest
  """
  `get_min_proto_version` on a disposed context returns `SslAutoVersion` rather
  than passing a null `SSL_CTX*` to `SSL_CTX_ctrl`.

  `create` sets the minimum to `Tls1u2Version`, so the `SslAutoVersion`
  afterwards is not the value a live context would have returned.

  This test passes with and without the disposed check on OpenSSL, whose
  `SSL_CTX_ctrl` returns 0 for a null context. LibreSSL's dereferences it, so
  LibreSSL is where the check keeps this from being a crash.
  """
  fun name(): String => "net/ssl/SSLContext.get_min_proto_version/after_dispose"

  fun apply(h: TestHelper) =>
    let ctx = SSLContext

    h.assert_eq[ILong](
      Tls1u2Version().ilong(),
      ctx.get_min_proto_version(),
      "create() should have set the minimum protocol version to TLS v1.2")

    ctx.dispose()

    h.assert_eq[ILong](
      SslAutoVersion().ilong(),
      ctx.get_min_proto_version(),
      "get_min_proto_version() on a disposed context should return "
        + "SslAutoVersion")

class \nodoc\ iso _TestSSLContextGetMaxProtoVersionAfterDispose is UnitTest
  """
  `get_max_proto_version` on a disposed context returns `SslAutoVersion` rather
  than passing a null `SSL_CTX*` to `SSL_CTX_ctrl`.

  `create` leaves the maximum at `SslAutoVersion`, so this test sets it to
  `Tls1u3Version` first. Without that, the assertion after the dispose would
  hold for a live context too.

  Carries the same caveat as
  `net/ssl/SSLContext.get_min_proto_version/after_dispose`: only LibreSSL
  crashes without the check.
  """
  fun name(): String => "net/ssl/SSLContext.get_max_proto_version/after_dispose"

  fun apply(h: TestHelper) =>
    let ctx = SSLContext

    try
      ctx.set_max_proto_version(Tls1u3Version())?
    else
      h.fail("set_max_proto_version() on a live context should not raise")
      return
    end

    h.assert_eq[ILong](
      Tls1u3Version().ilong(),
      ctx.get_max_proto_version(),
      "the maximum protocol version should read back as TLS v1.3")

    ctx.dispose()

    h.assert_eq[ILong](
      SslAutoVersion().ilong(),
      ctx.get_max_proto_version(),
      "get_max_proto_version() on a disposed context should return "
        + "SslAutoVersion")

class \nodoc\ iso _TestSSLContextGetMinProtoVersionOnValReceiver is UnitTest
  """
  `get_min_proto_version` reads through a `val` receiver.

  Configuring a context and then holding it `val` is what `client` and `server`
  require. A `fun ref` getter cannot be called on a `val` receiver, so this file
  stops compiling if that capability comes back.

  `create` sets the minimum to `Tls1u2Version`, so the assertion is on a value
  the getter had to read out of the context rather than on a default.
  """
  fun name(): String =>
    "net/ssl/SSLContext.get_min_proto_version/on_val_receiver"

  fun apply(h: TestHelper) =>
    let ctx: SSLContext val = recover val SSLContext end

    h.assert_eq[ILong](
      Tls1u2Version().ilong(),
      ctx.get_min_proto_version(),
      "a val receiver should read back the minimum that create() set")

class \nodoc\ iso _TestSSLContextGetMaxProtoVersionOnValReceiver is UnitTest
  """
  `get_max_proto_version` reads through a `val` receiver.

  Configuring a context and then holding it `val` is what `client` and `server`
  require. A `fun ref` getter cannot be called on a `val` receiver, so this file
  stops compiling if that capability comes back.

  `create` leaves the maximum at `SslAutoVersion`, so this context sets it to
  `Tls1u3Version` before it freezes. Without that, the assertion would hold
  for a context whose maximum was never set.
  """
  fun name(): String =>
    "net/ssl/SSLContext.get_max_proto_version/on_val_receiver"

  fun apply(h: TestHelper) ? =>
    let ctx: SSLContext val =
      recover val
        SSLContext .> set_max_proto_version(Tls1u3Version())?
      end

    h.assert_eq[ILong](
      Tls1u3Version().ilong(),
      ctx.get_max_proto_version(),
      "a val receiver should read back the maximum that was set")

class \nodoc\ iso _TestSSLCanSendOnValReceiver is UnitTest
  """
  `can_send` reads through a `val` receiver.

  It reads whether the session has bytes waiting and changes nothing, so a `val`
  session can call it. A `fun ref` `can_send` could not, and this file stops
  compiling if that capability comes back.

  A fresh client session has a ClientHello waiting, so `can_send` reads `true`
  and the assertion is on a value it had to read out of the session. A `val`
  session cannot be disposed, so the garbage collector frees it.
  """
  fun name(): String => "net/ssl/SSL.can_send/on_val_receiver"

  fun apply(h: TestHelper) =>
    try
      (let client: SSL val, _) = _TestSSLContext(h)?

      h.assert_true(
        client.can_send(),
        "a fresh client session should have a ClientHello to send")
    else
      h.fail("could not create an SSL session")
    end

class \nodoc\ iso _TestSSLContextSetAuthorityRootCertsAfterDispose is UnitTest
  """
  `set_authority(None, None)` on a disposed context raises an error rather than
  loading the system root certificates into a null `SSL_CTX*`.

  On Posix this raises whether or not the context is disposed; there are no
  system root certificates to load and the method has always raised. On Windows
  a live context loads them, and a disposed one used to reach
  `SSL_CTX_set_cert_store` with a null context and crash. Windows CI is where
  this test earns its keep.
  """
  fun name(): String =>
    "net/ssl/SSLContext.set_authority/root_certs_after_dispose"

  fun apply(h: TestHelper) =>
    let ctx = SSLContext

    ctx.dispose()

    try
      ctx.set_authority(None, None)?
      h.fail("set_authority(None, None) on a disposed context should raise")
    end

class \nodoc\ iso _TestSSLContextSetAuthorityAfterDispose is UnitTest
  """
  `set_authority` on a disposed context raises an error. This locks in a guard
  the disposed context already had.
  """
  fun name(): String => "net/ssl/SSLContext.set_authority/after_dispose"

  fun apply(h: TestHelper) =>
    let auth = FileAuth(h.env.root)
    let ctx = SSLContext

    try
      ctx.set_authority(FilePath(auth, "assets/cert.pem"))?
    else
      h.fail("set_authority() on a live context should not raise")
    end

    ctx.dispose()

    try
      ctx.set_authority(FilePath(auth, "assets/cert.pem"))?
      h.fail("set_authority() on a disposed context should raise")
    end

class \nodoc\ iso _TestSSLContextSetCertAfterDispose is UnitTest
  """
  `set_cert` on a disposed context raises an error. This locks in a guard the
  disposed context already had.
  """
  fun name(): String => "net/ssl/SSLContext.set_cert/after_dispose"

  fun apply(h: TestHelper) =>
    let auth = FileAuth(h.env.root)
    let cert = FilePath(auth, "assets/cert.pem")
    let key = FilePath(auth, "assets/key.pem")
    let ctx = SSLContext

    try
      ctx.set_cert(cert, key)?
    else
      h.fail("set_cert() on a live context should not raise")
    end

    ctx.dispose()

    try
      ctx.set_cert(cert, key)?
      h.fail("set_cert() on a disposed context should raise")
    end

class \nodoc\ iso _TestSSLContextSetCiphersAfterDispose is UnitTest
  """
  `set_ciphers` on a disposed context raises an error. This locks in a guard the
  disposed context already had.

  The cipher list is one a live context accepts, so the error after the dispose
  is the disposed check and not the invalid-cipher-list error.
  """
  fun name(): String => "net/ssl/SSLContext.set_ciphers/after_dispose"

  fun apply(h: TestHelper) =>
    let ctx = SSLContext

    try
      ctx.set_ciphers("HIGH")?
    else
      h.fail("set_ciphers(\"HIGH\") on a live context should not raise")
    end

    ctx.dispose()

    try
      ctx.set_ciphers("HIGH")?
      h.fail("set_ciphers() on a disposed context should raise")
    end

class \nodoc\ iso _TestSSLContextSetVerifyDepthAfterDispose is UnitTest
  """
  `set_verify_depth` on a disposed context does nothing. This locks in a guard
  the disposed context already had; without it, `SSL_CTX_set_verify_depth`
  dereferences the null context on every backend.

  There is nothing to observe beyond the call returning, so the context is
  checked for inertness afterwards. The call before the dispose is the only one
  in the suite that carries a depth into `SSL_CTX_set_verify_depth`.
  """
  fun name(): String => "net/ssl/SSLContext.set_verify_depth/after_dispose"

  fun apply(h: TestHelper) =>
    let ctx = SSLContext

    ctx.set_verify_depth(4)

    ctx.dispose()
    ctx.set_verify_depth(4)

    // A live context accepts this protocol list, so a `false` here is the
    // context still being disposed and not a list it rejected.
    h.assert_false(
      ctx.alpn_set_client_protocols(["h2"]),
      "the context should still be disposed")

class \nodoc\ iso _TestSSLContextAllowTlsAfterDispose is UnitTest
  """
  `allow_tls_v1`, `allow_tls_v1_1` and `allow_tls_v1_2` on a disposed context do
  nothing. This locks in guards the disposed context already had.

  Unlike the protocol version methods, these catch a missing guard on every
  backend. They reach `SSL_CTX_set_options` and `SSL_CTX_clear_options` on
  OpenSSL and `SSL_CTX_ctrl` on LibreSSL, and all three dereference the null
  context.

  Both states of each are exercised, because one clears an option and the other
  sets it, and they reach different C functions on OpenSSL.
  """
  fun name(): String => "net/ssl/SSLContext.allow_tls/after_dispose"

  fun apply(h: TestHelper) =>
    let ctx = SSLContext

    ctx.dispose()

    ctx.allow_tls_v1(true)
    ctx.allow_tls_v1(false)
    ctx.allow_tls_v1_1(true)
    ctx.allow_tls_v1_1(false)
    ctx.allow_tls_v1_2(true)
    ctx.allow_tls_v1_2(false)

    // A live context accepts this protocol list, so a `false` here is the
    // context still being disposed and not a list it rejected.
    h.assert_false(
      ctx.alpn_set_client_protocols(["h2"]),
      "the context should still be disposed")

class \nodoc\ iso _TestSSLContextAllowTlsV1u2 is UnitTest
  """
  `allow_tls_v1_2` takes effect on a live context.

  The context permits TLS 1.2 and nothing else, so disabling TLS 1.2 leaves the
  handshake no version to negotiate. Re-enabling it clears the option and the
  handshake completes again.

  The first assertion is the control. Without it, a handshake that failed for
  an unrelated reason would look like the option taking effect.

  The context is live, so `SSLContext._set_options` and `_clear_options` reach
  the SSL library rather than returning at the disposed check.
  """
  fun name(): String => "net/ssl/SSLContext.allow_tls_v1_2"

  fun apply(h: TestHelper) =>
    h.assert_true(
      _handshakes(h, false, false),
      "a context pinned to TLS 1.2 should complete a handshake")

    h.assert_false(
      _handshakes(h, true, false),
      "disabling TLS 1.2 should leave no version to negotiate")

    h.assert_true(
      _handshakes(h, true, true),
      "re-enabling TLS 1.2 should let the handshake complete again")

  fun _handshakes(h: TestHelper, disable: Bool, reenable: Bool): Bool =>
    """
    Whether a client and a server session from a TLS 1.2 only context complete
    a handshake, having disabled and then re-enabled TLS 1.2 as asked.
    """
    let auth = FileAuth(h.env.root)
    let sslctx =
      try
        recover val
          let ctx = SSLContext
            .> set_authority(FilePath(auth, "assets/cert.pem"))?
            .> set_cert(
                FilePath(auth, "assets/cert.pem"),
                FilePath(auth, "assets/key.pem"))?
            .> set_client_verify(false)
            .> set_server_verify(false)
            .> set_min_proto_version(Tls1u2Version())?
            .> set_max_proto_version(Tls1u2Version())?
          if disable then ctx.allow_tls_v1_2(false) end
          if reenable then ctx.allow_tls_v1_2(true) end
          ctx
        end
      else
        h.fail("ssl context setup failed")
        return false
      end

    let client: SSL =
      try
        sslctx.client()?
      else
        h.fail("failed getting ssl client session")
        return false
      end

    let server: SSL =
      try
        sslctx.server()?
      else
        client.dispose()
        h.fail("failed getting ssl server session")
        return false
      end

    let ready = _drive(client, server)
    client.dispose()
    server.dispose()
    ready

  fun _drive(client: SSL, server: SSL): Bool =>
    """
    Whether both sides reach `SSLReady` when each side's outgoing bytes are
    handed straight to the other.

    A handshake with no protocol version left to negotiate fails rather than
    stalls, so the loop ends on its own. The round cap is a backstop against a
    session that never settles, not the expected way out.
    """
    let max_rounds: USize = 20
    var rounds: USize = 0

    while
      (client.state() is SSLHandshake) or (server.state() is SSLHandshake)
    do
      if rounds == max_rounds then return false end
      rounds = rounds + 1

      try
        _TestSSLTransfer(client, server)?
        _TestSSLTransfer(server, client)?
      else
        return false
      end
    end

    (client.state() is SSLReady) and (server.state() is SSLReady)

class \nodoc\ iso _TestSSLContextClientAfterDispose is UnitTest
  """
  `client` on a disposed context raises an error rather than handing a null
  context to `SSL_new`.

  Two things make it raise and the test cannot tell them apart: `SSL._create`
  checks the context before it calls `SSL_new`, and `SSL_new` returns null for a
  null context on every backend, which `SSL._create` raises on as well.
  """
  fun name(): String => "net/ssl/SSLContext.client/after_dispose"

  fun apply(h: TestHelper) =>
    let live: SSLContext val = recover val SSLContext end

    try
      live.client()?.dispose()
    else
      h.fail("client() on a live context should not raise")
    end

    // `client` needs an immutable context, so dispose the mutable one first and
    // then freeze it to call `client` on the disposed result.
    let mutable: SSLContext iso = recover iso SSLContext end
    mutable.dispose()
    let disposed: SSLContext val = consume mutable

    try
      disposed.client()?.dispose()
      h.fail("client() on a disposed context should raise")
    end

class \nodoc\ iso _TestSSLContextServerAfterDispose is UnitTest
  """
  `server` on a disposed context raises an error rather than handing a null
  context to `SSL_new`.

  Carries the same caveat as `net/ssl/SSLContext.client/after_dispose`: the
  context check in `SSL._create` and `SSL_new` returning null both produce the
  error, and the test cannot tell them apart.
  """
  fun name(): String => "net/ssl/SSLContext.server/after_dispose"

  fun apply(h: TestHelper) =>
    let live: SSLContext val = recover val SSLContext end

    try
      live.server()?.dispose()
    else
      h.fail("server() on a live context should not raise")
    end

    // `server` needs an immutable context, so dispose the mutable one first and
    // then freeze it to call `server` on the disposed result.
    let mutable: SSLContext iso = recover iso SSLContext end
    mutable.dispose()
    let disposed: SSLContext val = consume mutable

    try
      disposed.server()?.dispose()
      h.fail("server() on a disposed context should raise")
    end

class \nodoc\ iso _TestALPNProtocolListRoundTrip is Property1[Array[String]]
  fun name(): String =>
    "net/ssl/_ALPNProtocolList/property/roundtrip"

  fun gen(): Generator[Array[String]] =>
    Generators.array_of[String](
      Generators.ascii_printable(1, 20) where min = 1, max = 5)

  fun ref property(sample: Array[String], h: PropertyHelper) ? =>
    let encoded = _ALPNProtocolList.from_array(sample)?
    let decoded = _ALPNProtocolList.to_array(encoded)?
    h.assert_eq[USize](sample.size(), decoded.size())
    var i: USize = 0
    while i < sample.size() do
      h.assert_true(sample(i)? == decoded(i)?)
      i = i + 1
    end

class \nodoc\ iso _TestMatchNameEmptyName is UnitTest
  fun name(): String => "net/ssl/X509._match_name/empty_name"

  fun apply(h: TestHelper) =>
    h.assert_false(X509._match_name("example.com", ""))
    h.assert_false(X509._match_name("localhost", ""))
    h.assert_false(X509._match_name("192.168.1.1", ""))

class \nodoc\ iso _TestMatchNameExactCaseInsensitive is UnitTest
  fun name(): String => "net/ssl/X509._match_name/exact_case_insensitive"

  fun apply(h: TestHelper) =>
    h.assert_true(X509._match_name("example.com", "example.com"))
    h.assert_true(X509._match_name("Example.COM", "example.com"))
    h.assert_true(X509._match_name("example.com", "EXAMPLE.COM"))

class \nodoc\ iso _TestMatchNameNoMatch is UnitTest
  fun name(): String => "net/ssl/X509._match_name/no_match"

  fun apply(h: TestHelper) =>
    h.assert_false(X509._match_name("example.com", "other.com"))
    h.assert_false(X509._match_name("example.com", "example.org"))

class \nodoc\ iso _TestMatchNameIPLiteral is UnitTest
  fun name(): String => "net/ssl/X509._match_name/ip_literal"

  fun apply(h: TestHelper) =>
    h.assert_true(X509._match_name("192.168.1.1", "192.168.1.1"))
    h.assert_false(X509._match_name("192.168.1.1", "192.168.1.2"))
    // IP literals require exact match, not case-insensitive domain match
    h.assert_false(X509._match_name("192.168.1.1", "*.168.1.1"))

class \nodoc\ iso _TestMatchNameWildcard is UnitTest
  fun name(): String => "net/ssl/X509._match_name/wildcard"

  fun apply(h: TestHelper) =>
    h.assert_true(X509._match_name("foo.example.com", "*.example.com"))
    h.assert_true(X509._match_name("FOO.Example.COM", "*.example.com"))

class \nodoc\ iso _TestMatchNameWildcardInsufficientLevels is UnitTest
  fun name(): String =>
    "net/ssl/X509._match_name/wildcard_insufficient_levels"

  fun apply(h: TestHelper) =>
    // Wildcard alone is not valid
    h.assert_false(X509._match_name("example.com", "*"))
    // Wildcard with only one domain level is not valid
    h.assert_false(X509._match_name("example.com", "*."))
    // Wildcard followed by dot-dot is not valid
    h.assert_false(X509._match_name("foo.example.com", "*..com"))
