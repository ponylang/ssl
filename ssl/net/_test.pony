use "pony_test"
use "pony_check"
use "itertools"
use "files"
use "net"

actor \nodoc\ Main is TestList
  new create(env: Env) => PonyTest(env, this)
  new make() => None

  fun tag tests(test: PonyTest) =>
    test(_TestALPNProtocolListEncoding)
    test(_TestALPNProtocolListDecode)
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
        recover
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
        recover
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
        recover
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
  TLS handshake with the default `_client_verify = true` and a hostname
  NOT matching the test certificate's SAN. The handshake itself succeeds
  (self-signed CA is trusted) but X509.valid_for_host rejects the
  hostname, SSL state becomes SSLAuthFail, and SSLConnection forwards
  `auth_failed` to the wrapped notify. Complements the positive test by
  proving that hostname matching actually gates the outcome; without
  this, a trivially broken `valid_for_host` that always returned true
  would pass the positive test.

  Uses separate client and server SSLContexts for the same reason as
  the positive test — see `_TestTCPSSLPeerCertificateVerify`.

  Note: the test asserts SSLAuthFail is reached but cannot by itself
  distinguish a hostname-mismatch failure from any other auth failure
  (e.g. chain validation). The pair with `_TestTCPSSLPeerCertificateVerify`
  — which would also fail under a broken chain — provides the
  distinguishing signal.
  """
  fun name(): String => "net/TCPSSL.peer_certificate_hostname_mismatch"
  fun exclusion_group(): String => "network"

  fun ref apply(h: TestHelper) =>
    h.expect_action("client auth failed")

    let auth = FileAuth(h.env.root)
    let client_ctx =
      try
        recover
          SSLContext
            .> set_authority(FilePath(auth, "assets/cert.pem"))?
        end
      else
        h.fail("client ssl context setup failed")
        return
      end
    let server_ctx =
      try
        recover
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
        recover
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
        recover
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
    let auth = FileAuth(h.env.root)

    // The resolver is handed to OpenSSL as callback data, which the Pony GC
    // cannot see. Hold it here so it outlives the handshake.
    let resolver = ALPNStandardProtocolResolver(["h2"])

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
            .> alpn_set_client_protocols(["h2"])
            .> alpn_set_resolver(resolver)
        end
      else
        h.fail("ssl context setup failed")
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
