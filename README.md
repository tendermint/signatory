# ![Signatory](https://miscreant.io/images/signatory.svg)

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![MIT/Apache2 licensed][license-image]

[crate-image]: https://img.shields.io/crates/v/signatory.svg
[crate-link]: https://crates.io/crates/signatory
[docs-image]: https://docs.rs/signatory/badge.svg
[docs-link]: https://docs.rs/signatory/
[build-image]: https://circleci.com/gh/tendermint/signatory.svg?style=shield
[build-link]: https://circleci.com/gh/tendermint/signatory
[license-image]: https://img.shields.io/badge/license-MIT/Apache2.0-blue.svg

A pure Rust multi-provider digital signature library for Rust with support for
the Ed25519 elliptic curve public-key signature system described in [RFC 8032].

[Documentation](https://docs.rs/signatory/)

[RFC 8032]: https://tools.ietf.org/html/rfc8032

## About

Signatory exposes an object-safe API for creating digital signatures which
allows several signature providers to be compiled-in and available with
specific providers selected at runtime.

## Provider Support

[cargo features] are used to select which providers are compiled-in:

### Ed25519 providers

* `dalek-provider`<sup>*</sup>: provider for the [ed25519-dalek] crate
* `yubihsm-provider`: provider for the [yubihsm2-rs] supporting [YubiHSM2] devices 

<sup>*</sup> Enabled by default

[cargo features]: https://doc.rust-lang.org/cargo/reference/manifest.html#the-features-section
[ed25519-dalek]: https://github.com/dalek-cryptography/ed25519-dalek
[yubihsm-rs]: https://github.com/tendermint/yubihsm-rs
[YubiHSM2]: https://www.yubico.com/products/yubihsm/

### YubiHSM2 Provider Notes

The [yubihsm-rs] crate depends on the `aesni` crate, which uses the new "stdsimd" API
(which recently landed in nightly) to invoke hardware AES instructions via
`core::arch`.

To access these features, you will need both a relatively recent
Rust nightly and to pass the following as RUSTFLAGS:

```
RUSTFLAGS=-C target-feature=+aes`
```

You can configure your `~/.cargo/config` to always pass these flags:

```toml
[build]
rustflags = ["-C", "target-feature=+aes"]
```

## License

Signatory is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
