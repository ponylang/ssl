## Fix Digest leaking memory when final() is never called

A `Digest` that was built and then dropped without a call to `final()` never gave back the memory it allocated. A program that abandoned digests — because a request was cancelled, or an error was raised partway through — grew its memory use with every digest it dropped.

Dropping a digest without calling `final()` is now safe. The memory comes back when the garbage collector collects the digest. Calling `final()` frees it as before.
