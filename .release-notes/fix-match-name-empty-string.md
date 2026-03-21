## Fix X509 hostname verification accepting empty certificate names

`X509.valid_for_host` could incorrectly report that a certificate was valid for any hostname when the certificate's name list contained an empty string. An empty name now correctly fails to match any hostname.
