use "net"

interface ALPNProtocolNotify
  """
  A `TCPConnectionNotify` that also implements this is told the protocol ALPN
  negotiated, once the handshake is complete.
  """
  fun ref alpn_negotiated(conn: TCPConnection, protocol: (String | None)): None
    """
    The protocol the peers agreed on, or `None` when they agreed on none.
    Called once, before any application data reaches `received`.
    """
