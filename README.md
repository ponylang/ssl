# ssl

Pony wrappers for OpenSSL and LibreSSL.

## Status

Production ready.

## Installation

* Install [corral](https://github.com/ponylang/corral)
* `corral add github.com/ponylang/ssl.git --version 2.1.0`
* `corral fetch` to fetch your dependencies
* `use "ssl/crypto"` to include the `crypto` sub-package
* `use "ssl/net"` to include the `net` sub-package
* `corral run -- ponyc` to compile your application

## Supported SSL versions

OpenSSL 3.0.x, OpenSSL 4.0.x, LibreSSL, and OpenSSL 1.1.x are supported. Select the library version at compile-time using Pony's compile time definition functionality.

Not every supported backend is still actively maintained upstream. OpenSSL 1.1.x reached end-of-life in September 2023 and no longer receives public security fixes. It remains available here for legacy use only. OpenSSL 3.0.x, OpenSSL 4.0.x, and LibreSSL are actively maintained.

### Using OpenSSL 3.0.x

```bash
corral run -- ponyc -Dopenssl_3.0.x
```

### Using OpenSSL 4.0.x

```bash
corral run -- ponyc -Dopenssl_4.0.x
```

### Using LibreSSL

```bash
corral run -- ponyc -Dlibressl
```

### Using OpenSSL 1.1.x (legacy)

```bash
corral run -- ponyc -Dopenssl_1.1.x
```

## Dependencies

`ssl` requires either LibreSSL or OpenSSL in order to operate. You might need to install it within your environment of choice.

### Installing on APT based Linux distributions

```bash
sudo apt-get install -y libssl-dev
```

### Installing on Alpine Linux

```bash
apk add --update libressl-dev
```

### Installing on Arch Linux

```bash
pacman -S openssl

```

### Installing on macOS with Homebrew

```bash
brew update
brew install libressl
```

#### Installing on macOS with MacPorts

```bash
sudo port install libressl
```

### Installing on RPM based Linux distributions with dnf

```bash
sudo dnf install openssl-devel
```

### Installing on RPM based Linux distributions with yum

```bash
sudo yum install openssl-devel
```

### Installing on RPM based Linux distributions with zypper

```bash
sudo zypper install libopenssl-devel
```

### Installing on Windows

Install one of the supported SSL libraries.

## API Documentation

[https://ponylang.github.io/ssl](https://ponylang.github.io/ssl)
