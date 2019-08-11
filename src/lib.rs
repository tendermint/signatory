//! Signatory: a multi-provider digital signature library
//!
//! This crate provides a thread-and-object-safe API for both creating and
//! verifying elliptic curve digital signatures, using either software-based
//! or hardware-based providers.
//!
//! The following algorithms are supported:
//!
//! - [ecdsa]: Elliptic Curve Digital Signature Algorithm ([FIPS 186-4])
//! - [ed25519]: Edwards Digital Signature Algorithm (EdDSA) instantiated using
//!   the twisted Edwards form of Curve25519 ([RFC 8032]).
//!
//! ## Providers
//!
//! There are several backend providers available, which are each available
//! in their own crates:
//!
//! - [signatory-dalek]: Ed25519 signing/verification using the pure-Rust
//!   [ed25519-dalek] crate.
//! - [signatory-ring]: ECDSA and Ed25519 signing/verification provider
//!   for the [*ring*] cryptography library.
//! - [signatory-secp256k1]: ECDSA signing/verification for the secp256k1
//!   elliptic curve (commonly used by Bitcoin and other cryptocurrrencies)
//!   which wraps the [libsecp256k1] library from Bitcoin Core.
//! - [signatory-sodiumoxide]: Ed25519 signing/verification with the
//!   [sodiumoxide] crate, a Rust wrapper for libsodium (NOTE: requires
//!   libsodium to be installed on the system)
//! - [yubihsm-rs]: ECDSA and Ed25519 signing provider support for
//!   private keys stored in a `YubiHSM2` hardware device, via the
//!   Signatory signers types in the [yubihsm-rs] crate
//!   ([yubihsm::ecdsa::Signer] and [yubihsm::ed25519::Signer]).
//!
//! ## Signing API
//!
//! - [Signer]: trait for signing
//! - [DigestSigner]: trait for signing digests
//!
//! ## Verifier API
//!
//! - [Verifier]: trait for verifying
//! - [DigestVerifier]: trait for verifying digests
//!
//! [FIPS 186-4]: https://csrc.nist.gov/publications/detail/fips/186/4/final
//! [RFC 8032]: https://tools.ietf.org/html/rfc8032
//! [ecdsa]: https://docs.rs/signatory/latest/signatory/ecdsa/index.html
//! [ed25519]: https://docs.rs/signatory/latest/signatory/ed25519/index.html
//! [signatory-dalek]: https://docs.rs/crate/signatory-dalek/
//! [ed25519-dalek]: https://docs.rs/crate/ed25519-dalek/
//! [signatory-ring]: https://docs.rs/crate/signatory-ring/
//! [*ring*]: https://github.com/briansmith/ring
//! [signatory-secp256k1]: https://docs.rs/crate/signatory-secp256k1/
//! [libsecp256k1]: https://docs.rs/crate/secp256k1
//! [signatory-sodiumoxide]: https://docs.rs/crate/signatory-sodiumoxide/
//! [sodiumoxide]: https://docs.rs/crate/sodiumoxide/
//! [yubihsm-rs]: https://docs.rs/crate/yubihsm/
//! [yubihsm::ecdsa::Signer]: https://docs.rs/yubihsm/latest/yubihsm/ecdsa/struct.Signer.html
//! [yubihsm::ed25519::Signer]: https://docs.rs/yubihsm/latest/yubihsm/ed25519/struct.Signer.html
//! [Signer]: https://docs.rs/signatory/latest/signatory/trait.Signer.html
//! [DigestSigner]: https://docs.rs/signatory/latest/signatory/trait.DigestSigner.html
//! [Verifier]: https://docs.rs/signatory/latest/signatory/trait.Verifier.html
//! [DigestVerifier]: https://docs.rs/signatory/latest/signatory/trait.DigestVerifier.html

#![no_std]
#![deny(warnings, missing_docs, trivial_casts, unused_qualifications)]
#![forbid(unsafe_code)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tendermint/signatory/develop/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory/0.13.0"
)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
#[allow(unused_imports)] // rustc bug?
#[macro_use]
extern crate alloc;

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "ed25519")]
#[macro_use]
pub mod ed25519;
#[cfg(feature = "encoding")]
pub mod encoding;
mod prelude;
pub mod public_key;
#[cfg(feature = "test-vectors")]
pub mod test_vector;
mod util;
#[cfg(feature = "generic-array")]
pub use generic_array;
#[cfg(feature = "sha2")]
pub use sha2;
pub use signature;
