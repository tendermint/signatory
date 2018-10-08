# ![Signatory](https://www.iqlusion.io/img/github/tendermint/signatory/signatory.svg)

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

A pure Rust multi-provider digital signature library with support for elliptic
curve digital signature algorithms, namely ECDSA (described in [FIPS 186‑4])
and Ed25519 (described in [RFC 8032]).

Signatory provides a thread-safe and object-safe API and implements providers
for many popular Rust crates, including [ed25519‑dalek], [secp256k1‑rs], [ring],
and [sodiumoxide].

[Documentation](https://docs.rs/signatory/)

[FIPS 186‑4]: https://csrc.nist.gov/publications/detail/fips/186/4/final
[RFC 8032]: https://tools.ietf.org/html/rfc8032
[ed25519‑dalek]: https://github.com/dalek-cryptography/ed25519-dalek
[ring]: https://github.com/briansmith/ring
[secp256k1‑rs]: https://github.com/rust-bitcoin/rust-secp256k1/
[sodiumoxide]: https://github.com/dnaq/sodiumoxide
[yubihsm‑rs]: https://github.com/tendermint/yubihsm-rs

## About

Signatory exposes a thread-and-object-safe API for creating digital signatures
which allows several signature providers to be compiled-in and available with
specific providers selected at runtime.

## Provider Support

Signatory includes the following providers, which are each packaged into their
own respective crates:

### ECDSA providers

| Provider Crate        | Backend Crate  | Type | P‑256 | P‑384 | secp256k1 |
|-----------------------|----------------|------|-------|-------|-----------|
| [signatory‑ring]      | [ring]         | Soft | ✅    | ✅    | ⛔        |
| [signatory‑secp256k1] | [secp256k1‑rs] | Soft | ⛔    | ⛔    | ✅        |
| [signatory‑yubihsm]   | [yubihsm‑rs]   | Hard | ✅    | ✅    | ✅        |

### Ed25519 providers

| Provider Crate          | Backend Crate   | Type | Signing | Verification |
|-------------------------|-----------------|------|---------|--------------|
| [signatory‑dalek]       | [ed25519‑dalek] | Soft | 51 k/s  | 18 k/s       |
| [signatory‑ring]        | [ring]          | Soft | 47 k/s  | 16 k/s       |
| [signatory‑sodiumoxide] | [sodiumoxide]   | Soft | 38 k/s  | 15 k/s       |
| [signatory‑yubihsm]     | [yubihsm‑rs]    | Hard | ~8/s    | N/A          |

Above benchmarks performed using `cargo bench` on an Intel Xeon E3-1225 v5 @ 3.30GHz.

[signatory‑dalek]: https://crates.io/crates/signatory-dalek
[signatory‑ring]: https://crates.io/crates/signatory-ring
[signatory‑secp256k1]: https://crates.io/crates/signatory-secp256k1
[signatory‑sodiumoxide]: https://crates.io/crates/signatory-sodiumoxide
[signatory‑yubihsm]: https://crates.io/crates/signatory-yubihsm

## License

**Signatory** is distributed under the terms of either the MIT license or the
Apache License (Version 2.0), at your option.

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
