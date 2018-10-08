# signatory-yubihsm

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![MIT/Apache2 licensed][license-image]

[crate-image]: https://img.shields.io/crates/v/signatory-yubihsm.svg
[crate-link]: https://crates.io/crates/signatory-yubihsm
[docs-image]: https://docs.rs/signatory-yubihsm/badge.svg
[docs-link]: https://docs.rs/signatory-yubihsm/
[build-image]: https://circleci.com/gh/tendermint/signatory.svg?style=shield
[build-link]: https://circleci.com/gh/tendermint/signatory
[license-image]: https://img.shields.io/badge/license-MIT/Apache2.0-blue.svg

[Signatory] ECDSA ([FIPS 186-4]) and Ed25519 ([RFC 8032]) provider for [yubihsm-rs].

[Documentation](https://docs.rs/signatory-yubihsm/)

[Signatory]: https://github.com/tendermint/signatory
[FIPS 186-4]: https://csrc.nist.gov/publications/detail/fips/186/4/final
[RFC 8032]: https://tools.ietf.org/html/rfc8032
[yubihsm-rs]: https://github.com/tendermint/yubihsm-rs

### Installation

The [yubihsm-rs] crate depends on the `aes` crate, which uses hardware AES
instructions via `core::arch` (Rust 1.27+).

To access these features, you will need to pass the following as RUSTFLAGS:

```
RUSTFLAGS=-Ctarget-feature=+aes`
```

You can configure your `~/.cargo/config` to always pass these flags:

```toml
[build]
rustflags = ["-Ctarget-feature=+aes"]
```

## License

**Signatory** is distributed under the terms of either the MIT license or the
Apache License (Version 2.0), at your option.

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
