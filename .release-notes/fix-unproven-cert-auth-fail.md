## Fix unproven peer certificates reporting SSLError instead of SSLAuthFail

A peer that presents a certificate it cannot prove it holds — an impersonator with a copy of the certificate but not the matching private key — now reports `SSLAuthFail`. Previously it reported `SSLError`, so `SSLConnection` closed the connection without calling `auth_failed` on the wrapped notify.
