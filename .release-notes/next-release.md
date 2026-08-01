## Fix connections being closed after an unrelated SSL failure

A failed OpenSSL operation left error state on the scheduler thread that ran it. The next SSL session to read on that thread was treated as failed even when nothing was wrong with it, and its connection was closed. A rejected handshake was enough to start it, and so was a bad certificate path or an unusable cipher string given to `SSLContext`. A failed operation now affects only the session it happened on.

