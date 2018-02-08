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

A multi-provider digital signature library for Rust with support for the
Ed25519 elliptic curve public-key signature system described in [RFC 8032].

[RFC 8032]: https://tools.ietf.org/html/rfc8032

## About

Signatory exposes an object-safe API for creating digital signatures which
allows several signature providers to be compiled-in and available with
specific providers selected at runtime.

Signatory presently supports the following providers:

* [ed25519-dalek] - pure Rust software implementation of Ed25519
* YubiHSM2 - forthcoming!

[ed25519-dalek]: https://github.com/dalek-cryptography/ed25519-dalek

## License

Signatory is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
