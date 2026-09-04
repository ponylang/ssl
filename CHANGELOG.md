# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/) and [Keep a CHANGELOG](http://keepachangelog.com/).

## [unreleased] - unreleased

### Fixed


### Added


### Changed


## [5.0.0] - 2026-09-04

### Changed

- Update to work with ponyc 0.70.0 ([PR #166](https://github.com/ponylang/ssl/pull/166))

## [4.1.0] - 2026-08-07

### Added

- Add DTLSContext and DTLS for datagram TLS ([PR #153](https://github.com/ponylang/ssl/pull/153))

## [4.0.0] - 2026-08-06

### Fixed

- Fix alpn_selected() returning a protocol from a failed session ([PR #149](https://github.com/ponylang/ssl/pull/149))

### Added

- Add SSL.close() and SSLClosed for orderly TLS shutdown ([PR #148](https://github.com/ponylang/ssl/pull/148))

### Changed

- Replace state polling with return values from receive, read, and send ([PR #152](https://github.com/ponylang/ssl/pull/152))

## [3.0.1] - 2026-08-02

### Fixed

- Fix connections being closed after an unrelated SSL failure ([PR #116](https://github.com/ponylang/ssl/pull/116))
- Fix SSL sessions returning uninitialized memory ([PR #124](https://github.com/ponylang/ssl/pull/124))
- Fix handshake failures being reported as authentication failures ([PR #126](https://github.com/ponylang/ssl/pull/126))
- Fix unproven peer certificates reporting SSLError instead of SSLAuthFail ([PR #133](https://github.com/ponylang/ssl/pull/133))
- Fix receive reporting inconsistent state when a callback contaminates the error queue ([PR #134](https://github.com/ponylang/ssl/pull/134))
- Fix read and alpn_selected returning data from authentication-failed sessions ([PR #136](https://github.com/ponylang/ssl/pull/136))
- Fix ssl/net silently losing data past two gibibytes ([PR #138](https://github.com/ponylang/ssl/pull/138))
- Fix SSL.write silently losing data when encryption fails ([PR #139](https://github.com/ponylang/ssl/pull/139))
- Fix client sessions not reporting immediate handshake failures ([PR #140](https://github.com/ponylang/ssl/pull/140))
- Fix SSLConnection calling auth_failed twice for one failure ([PR #141](https://github.com/ponylang/ssl/pull/141))
- Reject inverted protocol version range in SSLContext ([PR #142](https://github.com/ponylang/ssl/pull/142))

### Changed

- Report SSLAuthFail only for a peer certificate the session would not accept ([PR #126](https://github.com/ponylang/ssl/pull/126))

## [3.0.0] - 2026-07-10

### Fixed

- Fix crash when using a disposed SSL session ([PR #68](https://github.com/ponylang/ssl/pull/68))
- Fix crashes when using a disposed SSL context ([PR #73](https://github.com/ponylang/ssl/pull/73))
- Fix allow_tls_v1, allow_tls_v1_1 and allow_tls_v1_2 on 32-bit platforms ([PR #79](https://github.com/ponylang/ssl/pull/79))
- Fix ALPN resolver being collected while still in use ([PR #81](https://github.com/ponylang/ssl/pull/81))
- Fix Digest leaking memory when final() is never called ([PR #84](https://github.com/ponylang/ssl/pull/84))
- Allow non-mutating methods to be called on a val receiver ([PR #89](https://github.com/ponylang/ssl/pull/89))
- Fix leaks when loading Windows root certificates fails ([PR #90](https://github.com/ponylang/ssl/pull/90))
- Fix a potential use-after-free in ALPN protocol selection ([PR #91](https://github.com/ponylang/ssl/pull/91))
- Fix HmacSha256 returning an all-zero code when it fails ([PR #92](https://github.com/ponylang/ssl/pull/92))
- Fix Digest returning a wrong hash or crashing when OpenSSL fails ([PR #92](https://github.com/ponylang/ssl/pull/92))
- Fix crypto functions truncating a length too large for an int ([PR #92](https://github.com/ponylang/ssl/pull/92))

### Changed

- Add SSLDisposed to SSLState ([PR #68](https://github.com/ponylang/ssl/pull/68))
- Require a val resolver for alpn_set_resolver ([PR #81](https://github.com/ponylang/ssl/pull/81))
- Require a val context for SSLContext.client and server ([PR #81](https://github.com/ponylang/ssl/pull/81))
- Make Digest and HmacSha256 raise on failure ([PR #92](https://github.com/ponylang/ssl/pull/92))
- Rename the SSL, TLS and DTLS version primitives ([PR #103](https://github.com/ponylang/ssl/pull/103))
- Require a box receiver for ssl/crypto's apply methods ([PR #99](https://github.com/ponylang/ssl/pull/99))

## [2.1.0] - 2026-04-20

### Added

- Add OpenSSL 4.0.x support ([PR #47](https://github.com/ponylang/ssl/pull/47))

### Changed

- Use prebuilt LibreSSL binaries on Windows ([PR #38](https://github.com/ponylang/ssl/pull/38))

## [2.0.1] - 2026-03-21

### Fixed

- Fix X509 hostname verification accepting empty certificate names ([PR #35](https://github.com/ponylang/ssl/pull/35))

## [2.0.0] - 2026-02-12

### Fixed

- SSLConnection ignores _notify.received value ([PR #21](https://github.com/ponylang/ssl/pull/21))

### Added

- Add first-class LibreSSL support ([PR #18](https://github.com/ponylang/ssl/pull/18))
- Add variable-length output support to SHAKE digests ([PR #23](https://github.com/ponylang/ssl/pull/23))

### Changed

- Remove OpenSSL 0.9.0 support ([PR #19](https://github.com/ponylang/ssl/pull/19))

## [1.0.3] - 2026-02-12

### Added

- Add HMAC-SHA-256 primitive ([PR #16](https://github.com/ponylang/ssl/pull/16))
- Add PBKDF2-SHA-256 primitive ([PR #16](https://github.com/ponylang/ssl/pull/16))
- Add RandBytes primitive ([PR #16](https://github.com/ponylang/ssl/pull/16))

## [1.0.2] - 2026-02-10

### Fixed

- Fix set_client_verify(false) not disabling hostname verification ([PR #12](https://github.com/ponylang/ssl/pull/12))

## [1.0.1] - 2025-07-29

### Fixed

- Update Shake128 and Shake256 to work with OpenSSL 3.4 ([PR #5](https://github.com/ponylang/ssl/pull/5))

## [1.0.0] - 2025-07-16

### Added

- Initial version

