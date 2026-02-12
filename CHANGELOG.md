# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/) and [Keep a CHANGELOG](http://keepachangelog.com/).

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

