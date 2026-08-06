use "collections"
use "net"

class SSLConnection is TCPConnectionNotify
  """
  Wrap another protocol in an SSL connection.
  """
  let _notify: TCPConnectionNotify
  let _ssl: SSL
  var _connected: Bool = false
  var _expect: USize = 0
  var _closed: Bool = false
  var _auth_failed: Bool = false
  let _pending: List[ByteSeq] = _pending.create()
  var _accept_pending: Bool = false

  new iso create(notify: TCPConnectionNotify iso, ssl: SSL iso) =>
    """
    Initialise with a wrapped protocol and an SSL session.
    """
    _notify = consume notify
    _ssl = consume ssl

  fun ref accepted(conn: TCPConnection ref) =>
    """
    Swallow this event until the handshake is complete.
    """
    _accept_pending = true
    _drain_sends(conn)

  fun ref connecting(conn: TCPConnection ref, count: U32) =>
    """
    Forward to the wrapped protocol.
    """
    _notify.connecting(conn, count)

  fun ref connected(conn: TCPConnection ref) =>
    """
    Swallow this event until the handshake is complete.
    """
    _drain_sends(conn)

  fun ref connect_failed(conn: TCPConnection ref) =>
    """
    Forward to the wrapped protocol.
    """
    _notify.connect_failed(conn)

  fun ref sent(conn: TCPConnection ref, data: ByteSeq): ByteSeq =>
    """
    Pass the data to the SSL session and check for both new application data
    and new destination data.
    """
    let notified = _notify.sent(conn, data)
    if _connected then
      try
        _ssl.write(notified)?
      else
        return ""
      end
    else
      _pending.push(notified)
    end

    _read_and_send(conn)
    ""

  fun ref sentv(conn: TCPConnection ref, data: ByteSeqIter): ByteSeqIter =>
    """
    Pass each sequence to the SSL session and check for both new application
    data and new destination data. Returns an empty sequence: what leaves the
    connection is the ciphertext `_read_and_send` writes, not these bytes.
    """
    let ret = recover val Array[ByteSeq] end
    let data' = _notify.sentv(conn, data)
    for bytes in data'.values() do
      if _connected then
        try
          _ssl.write(bytes)?
        else
          return ret
        end
      else
        _pending.push(bytes)
      end
    end

    _read_and_send(conn)
    ret

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] iso,
    times: USize)
    : Bool
  =>
    """
    Pass the data to the SSL session and check for both new application data
    and new destination data.
    """
    match \exhaustive\ _ssl.receive(consume data)
    | SSLReady =>
      if not _connected then
        _connected = true
        if _accept_pending then
          _notify.accepted(conn)
        else
          _notify.connected(conn)
        end

        match _notify
        | let alpn_notify: ALPNProtocolNotify =>
          alpn_notify.alpn_negotiated(conn, _ssl.alpn_selected())
        end

        try
          while true do
            let bytes = try _pending.shift()? else break end
            _ssl.write(bytes)?
          end
        end
      end
    | SSLAuthFail =>
      if not _auth_failed then
        _auth_failed = true
        _notify.auth_failed(conn)
      end

      if not _closed then
        conn.close()
      end

      return true
    | SSLError =>
      if not _closed then
        conn.close()
      end

      return true
    | SSLAccepted => None
    | InvalidOperation =>
      if not _closed then
        conn.close()
      end

      return true
    end

    _read_and_send(conn)

  fun ref expect(conn: TCPConnection ref, qty: USize): USize =>
    """
    Keep track of the expect count for the wrapped protocol. Always tell the
    TCPConnection to read all available data.
    """
    _expect = _notify.expect(conn, qty)
    0

  fun ref closed(conn: TCPConnection ref) =>
    """
    Forward to the wrapped protocol.
    """
    _closed = true
    _ssl.close()
    _drain_sends(conn)
    _ssl.dispose()

    _connected = false
    _pending.clear()
    _notify.closed(conn)

  fun ref throttled(conn: TCPConnection ref) =>
    """
    Forward to the wrapped protocol.
    """
    _notify.throttled(conn)

  fun ref unthrottled(conn: TCPConnection ref) =>
    """
    Forward to the wrapped protocol.
    """
    _notify.unthrottled(conn)

  fun ref _read_and_send(conn: TCPConnection ref): Bool =>
    var continue_reading: Bool = true
    var received_called: USize = 0

    while true do
      match \exhaustive\ _ssl.read(_expect)
      | let r: Array[U8] iso =>
        received_called = received_called + 1
        if not _notify.received(conn, consume r, received_called) then
          continue_reading = false
          break
        end
      | None => break
      | SSLClosed => return _do_shutdown(conn)
      | SSLError | InvalidOperation =>
        if not _closed then
          conn.close()
        end
        return true
      end
    end

    _drain_sends(conn)
    continue_reading

  fun ref _drain_sends(conn: TCPConnection ref) =>
    while true do
      match \exhaustive\ _ssl.send()
      | let data: Array[U8] iso =>
        conn.write_final(consume data)
      | None => break
      end
    end

  fun ref _do_shutdown(conn: TCPConnection ref): Bool =>
    _ssl.close()
    _drain_sends(conn)
    if not _closed then
      conn.close()
    end
    true
