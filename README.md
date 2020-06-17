# 🚨 DEPRECATED 🚨 

This repo has been deprecated. Development work continues in [iqlusioninc/signatory](https://github.com/iqlusioninc/signatory). Please reference that repository in the future.

# ![Signatory][logo]

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![MSRV][rustc-image]
[![Build Status][build-image]][build-link]

Pure Rust multi-provider digital signature library with support for elliptic
curve digital signature algorithms, namely ECDSA (described in [FIPS 186‑4])
and Ed25519 (described in [RFC 8032]).

Signatory provides a thread-safe and object-safe API and implements providers
for many popular Rust crates, including [ed25519‑dalek], [*ring*], [secp256k1], 
and [sodiumoxide].

[Documentation][docs-link]

## About

Signatory exposes a thread-and-object-safe API for creating digital signatures
which allows several signature providers to be compiled-in and available with
specific providers selected at runtime.

## Requirements

All Signatory providers require Rust **1.37+**

## Provider Support

Signatory includes the following providers, which are each packaged into their
own respective crates (except for the [yubihsm] provider, which is included
[directly in the yubihsm crate]).

### ECDSA providers

| Provider Crate        | Backend Crate  | Type | P‑256  | P‑384  | secp256k1  |
| --------------------- | -------------- | ---- | ------ | ------ | ---------- |
| [signatory‑ring]      | [*ring*]       | Soft | ✅     | ✅     | ⛔         |
| [signatory‑secp256k1] | [secp256k1]    | Soft | ⛔     | ⛔     | ✅         |
| [yubihsm]             | [yubihsm]      | Hard | ✅     | ✅     | ✅         |

### Ed25519 providers

| Provider Crate          | Backend Crate   | Type | Signing | Verification |
| ----------------------- | --------------- | ---- | ------- | ------------ |
| [signatory‑dalek]       | [ed25519‑dalek] | Soft | 51 k/s  | 18 k/s       |
| [signatory‑ring]        | [*ring*]        | Soft | 47 k/s  | 16 k/s       |
| [signatory‑sodiumoxide] | [sodiumoxide]   | Soft | 38 k/s  | 15 k/s       |
| [yubihsm]               | [yubihsm]       | Hard | ~8/s    | N/A          |

### Tendermint only providers (amino encoded consensus votes)

| Provider Crate        | Backend Crate   | Type | Signing | Verification |
| --------------------- | --------------- | ---- | ------- | ------------ |
| [signatory‑ledger-tm] | [ledger-tendermint] | Hard | N/A     | N/A          |

Above benchmarks performed using `cargo bench` on an Intel Xeon E3-1225 v5 @ 3.30GHz.

## License

**Signatory** is distributed under the terms of either the MIT license or the
Apache License (Version 2.0), at your option.

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

[//]: # (badges)

[logo]: https://storage.googleapis.com/iqlusion-production-web/github/signatory/signatory.svg
[crate-image]: https://img.shields.io/crates/v/signatory.svg
[crate-link]: https://crates.io/crates/signatory
[docs-image]: https://docs.rs/signatory/badge.svg
[docs-link]: https://docs.rs/signatory/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.37+-blue.svg
[build-image]: https://github.com/iqlusioninc/signatory/workflows/Rust/badge.svg?branch=develop&event=push
[build-link]: https://github.com/iqlusioninc/signatory/actions

[//]: # (general links)

[FIPS 186‑4]: https://csrc.nist.gov/publications/detail/fips/186/4/final
[RFC 8032]: https://tools.ietf.org/html/rfc8032
[ed25519‑dalek]: https://github.com/dalek-cryptography/ed25519-dalek
[*ring*]: https://github.com/briansmith/ring
[secp256k1]: https://github.com/rust-bitcoin/rust-secp256k1/
[sodiumoxide]: https://github.com/dnaq/sodiumoxide
[yubihsm]: https://github.com/tendermint/yubihsm-rs
[ledger-tendermint]: https://crates.io/crates/ledger-tendermint
[directly in the yubihsm crate]: https://docs.rs/yubihsm/latest/yubihsm/signatory/index.html
[signatory‑dalek]: https://crates.io/crates/signatory-dalek
[signatory‑ring]: https://crates.io/crates/signatory-ring
[signatory‑secp256k1]: https://crates.io/crates/signatory-secp256k1
[signatory‑sodiumoxide]: https://crates.io/crates/signatory-sodiumoxide
[signatory‑ledger-tm]: https://crates.io/crates/signatory-ledger-tm
