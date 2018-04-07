# ![Signatory](https://miscreant.io/images/signatory.svg)

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![MIT/Apache2 licensed][license-image]

[crate-image]: https://img.shields.io/crates/v/signatory.svg?maxAge=2592000
[crate-link]: https://crates.io/crates/signatory
[docs-image]: https://docs.rs/signatory/badge.svg
[docs-link]: https://docs.rs/signatory/
[build-image]: https://circleci.com/gh/tendermint/signatory.svg?style=shield
[build-link]: https://circleci.com/gh/tendermint/signatory
[license-image]: https://img.shields.io/badge/license-MIT/Apache2.0-blue.svg

A pure Rust multi-provider digital signature library with support for elliptic
curve digital signature algorithms, namely ECDSA (described in [FIPS 186-4])
and Ed25519 (described in [RFC 8032]).

Signatory provides a thread-safe and object-safe API and implements providers
for many popular Rust crates, including [ed25519-dalek], [secp256k1], [ring],
and [sodiumoxide].

[Documentation](https://docs.rs/signatory/)

[FIPS 186-4]: https://csrc.nist.gov/publications/detail/fips/186/4/final
[RFC 8032]: https://tools.ietf.org/html/rfc8032
[ed25519-dalek]: https://github.com/dalek-cryptography/ed25519-dalek
[ring]: https://github.com/briansmith/ring
[secp256k1]: https://github.com/rust-bitcoin/rust-secp256k1/
[sodiumoxide]: https://github.com/dnaq/sodiumoxide
[yubihsm-rs]: https://github.com/tendermint/yubihsm-rs

## About

Signatory exposes a thread-and-object-safe API for creating digital signatures
which allows several signature providers to be compiled-in and available with
specific providers selected at runtime.

## Provider Support

Signatory includes the following providers, which can be enabled by selecting
the corresponding [cargo feature] for a given crate:

### ECDSA providers

| [Cargo Feature]      | Crate          | Type | Curve(s)  |
|----------------------|----------------|------|-----------| 
| `secp256k1-provider` | [secp256k1-rs] | Soft | secp256k1 |

### Ed25519 providers

| [Cargo Feature]        | Crate           | Type | Signing | Verification |
|------------------------|-----------------|------|---------|--------------|
| `dalek-provider`†      | [ed25519-dalek] | Soft | 43 k/s  | 17 k/s       |
| `ring-provider`        | [ring]          | Soft | 31 k/s  | 10 k/s       |
| `sodiumoxide-provider` | [sodiumoxide]   | Soft | 38 k/s  | 14 k/s       |
| `yubihsm-provider`     | [yubihsm-rs]    | Hard | ~8/s    | N/A          |

Above benchmarks performed using `cargo bench` on an Intel Xeon E3-1225 v5 @
3.30GHz with the `nightly` cargo feature enabled.

† NOTE: enabled by default

[cargo feature]: https://doc.rust-lang.org/cargo/reference/manifest.html#the-features-section

### YubiHSM2 Provider Notes

The [yubihsm-rs] crate depends on the `aesni` crate, which uses the new "stdsimd"
API (coming soon to stable!) to invoke hardware AES instructions via `core::arch`.

To access these features, you will need both a relatively recent
Rust nightly and to pass the following as RUSTFLAGS:

```
RUSTFLAGS=-Ctarget-feature=+aes`
```

You can configure your `~/.cargo/config` to always pass these flags:

```toml
[build]
rustflags = ["-Ctarget-feature=+aes"]
```

## License

Signatory is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
