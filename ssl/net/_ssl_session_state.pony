trait _SSLSessionState
  """
  Every SSL operation is dispatched through the current state.
  """
  fun ref receive(ssl: SSL ref, data: ByteSeq)
  fun ref read(ssl: SSL ref, expect: USize): (Array[U8] iso^ | None)
  fun ref write(ssl: SSL ref, data: ByteSeq) ?
  fun ref close(ssl: SSL ref)
  fun can_send(ssl: SSL box): Bool
  fun ref send(ssl: SSL ref): Array[U8] iso^ ?
  fun alpn_selected(ssl: SSL box): (ALPNProtocolName | None)
  fun ref dispose(ssl: SSL ref)
  fun state(): SSLState

class _Handshaking is _SSLSessionState
  fun ref receive(ssl: SSL ref, data: ByteSeq) =>
    ssl._do_receive(data)
    ssl._kick_handshake()

  fun ref read(ssl: SSL ref, expect: USize): (Array[U8] iso^ | None) => None

  fun ref write(ssl: SSL ref, data: ByteSeq) ? => error

  fun ref close(ssl: SSL ref) => None

  fun can_send(ssl: SSL box): Bool => ssl._do_can_send()

  fun ref send(ssl: SSL ref): Array[U8] iso^ ? => ssl._do_send()?

  fun alpn_selected(ssl: SSL box): (ALPNProtocolName | None) => None

  fun ref dispose(ssl: SSL ref) =>
    ssl._do_dispose()
    ssl._set_state(_Disposed)

  fun state(): SSLState => SSLHandshake

class _Ready is _SSLSessionState
  fun ref receive(ssl: SSL ref, data: ByteSeq) =>
    ssl._do_receive(data)

  fun ref read(ssl: SSL ref, expect: USize): (Array[U8] iso^ | None) =>
    ssl._do_read(expect)

  fun ref write(ssl: SSL ref, data: ByteSeq) ? =>
    ssl._do_write(data)?

  fun ref close(ssl: SSL ref) =>
    ssl._do_close_notify()

  fun can_send(ssl: SSL box): Bool => ssl._do_can_send()

  fun ref send(ssl: SSL ref): Array[U8] iso^ ? => ssl._do_send()?

  fun alpn_selected(ssl: SSL box): (ALPNProtocolName | None) =>
    ssl._do_alpn_selected()

  fun ref dispose(ssl: SSL ref) =>
    ssl._do_dispose()
    ssl._set_state(_Disposed)

  fun state(): SSLState => SSLReady

class _Closing is _SSLSessionState
  """
  Shutdown started but not yet complete. The peer sent `close_notify`;
  we have not responded yet.
  """

  fun ref receive(ssl: SSL ref, data: ByteSeq) =>
    ssl._do_receive(data)

  fun ref read(ssl: SSL ref, expect: USize): (Array[U8] iso^ | None) =>
    ssl._do_read(expect)

  fun ref write(ssl: SSL ref, data: ByteSeq) ? => error

  fun ref close(ssl: SSL ref) =>
    ssl._do_close_notify()

  fun can_send(ssl: SSL box): Bool => ssl._do_can_send()

  fun ref send(ssl: SSL ref): Array[U8] iso^ ? => ssl._do_send()?

  fun alpn_selected(ssl: SSL box): (ALPNProtocolName | None) =>
    ssl._do_alpn_selected()

  fun ref dispose(ssl: SSL ref) =>
    ssl._do_dispose()
    ssl._set_state(_Disposed)

  fun state(): SSLState => SSLClosed

class _Closed is _SSLSessionState
  """
  Shutdown complete. We have sent our `close_notify`.
  """

  fun ref receive(ssl: SSL ref, data: ByteSeq) =>
    ssl._do_receive(data)

  fun ref read(ssl: SSL ref, expect: USize): (Array[U8] iso^ | None) =>
    let result = ssl._do_read(expect)
    // _do_read sets _Closing on zero_return. We already sent close_notify,
    // so the correct state is still _Closed.
    if not (ssl.state() is SSLError) then
      ssl._set_state(this)
    end
    result

  fun ref write(ssl: SSL ref, data: ByteSeq) ? => error

  fun ref close(ssl: SSL ref) => None

  fun can_send(ssl: SSL box): Bool => ssl._do_can_send()

  fun ref send(ssl: SSL ref): Array[U8] iso^ ? => ssl._do_send()?

  fun alpn_selected(ssl: SSL box): (ALPNProtocolName | None) =>
    ssl._do_alpn_selected()

  fun ref dispose(ssl: SSL ref) =>
    ssl._do_dispose()
    ssl._set_state(_Disposed)

  fun state(): SSLState => SSLClosed

class _Disposed is _SSLSessionState
  fun ref receive(ssl: SSL ref, data: ByteSeq) => None

  fun ref read(ssl: SSL ref, expect: USize): (Array[U8] iso^ | None) => None

  fun ref write(ssl: SSL ref, data: ByteSeq) => None

  fun ref close(ssl: SSL ref) => None

  fun can_send(ssl: SSL box): Bool => false

  fun ref send(ssl: SSL ref): Array[U8] iso^ ? => error

  fun alpn_selected(ssl: SSL box): (ALPNProtocolName | None) => None

  fun ref dispose(ssl: SSL ref) => None

  fun state(): SSLState => SSLDisposed
