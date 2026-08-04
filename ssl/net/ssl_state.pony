primitive SSLHandshake
  """
  The session is still handshaking.
  """

primitive SSLAuthFail
  """
  The session rejected its peer's certificate.
  """

primitive SSLReady
  """
  The handshake is complete. Application data can be sent and received.
  """

primitive SSLClosed
  """
  The TLS session closed cleanly.
  """

primitive SSLError
  """
  The session failed with a protocol error or an I/O error.
  """

primitive SSLDisposed
  """
  The session has been disposed. Nothing more comes out of it.
  """

type SSLState is
  (SSLHandshake | SSLAuthFail | SSLReady | SSLClosed | SSLError | SSLDisposed)
  """
  The state of an SSL session.
  """
