## Update Shake128 and Shake256 to work with OpenSSL 3.4

With the introduction of OpenSSL 3.4, a breaking change was made to Shake128 and Shake256 digests. A default that previously existed for the digest size was removed, this meant that code still compiled but the digests for Shake128 and Shake256 came back as all 0's.

We've updated our Shake implementations to account and automatically supply the old default sizes. We will be looking at updating our API to support variable length digests in the future, but for now this should allow existing code to continue to work.

