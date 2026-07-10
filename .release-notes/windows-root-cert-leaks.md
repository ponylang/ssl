## Fix leaks when loading Windows root certificates fails

On Windows, `SSLContext.set_authority(None, None)` loads the system root certificates. Two of its failure paths leaked.

When it could not allocate the certificate store to copy the roots into, it raised an error and left the system certificate store open.

When adding one of the certificates failed partway through, it raised an error and abandoned the certificate it was reading at the time. Windows leaves that one to the caller to release, so its memory was never given back, and the system store's memory could not be released either while it was outstanding.

Both are released now before the error reaches the caller. Only Windows was affected, and only when one of those two calls failed.
