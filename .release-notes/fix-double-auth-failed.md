## Fix SSLConnection calling auth_failed twice for one failure

`SSLConnection` called `auth_failed` on the wrapped notify twice for a single authentication failure. The second call happened during `closed`. A notify that counted calls or performed side effects on each `auth_failed` received two calls.
