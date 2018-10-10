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
//!   ed25519-dalek crate. This provider is enabled-by-default.
//! - [signatory-ring]: ECDSA and Ed25519 signing/verification provider
//!   for the *ring* cryptography library.
//! - [signatory-secp256k1]: ECDSA signing/verification for the secp256k1
//!   elliptic curve (commonly used by Bitcoin and other cryptocurrrencies)
//!   which wraps the libsecp256k1 library from Bitcoin Core.
//! - [signatory-sodiumoxide]: Ed25519 signing/verification with the
//!   sodiumoxide crate, a Rust wrapper for libsodium (NOTE: requires
//!   libsodium to be installed on the system)
//! - [signatory-yubihsm]: ECDSA and Ed25519 signing provider which uses
//!   private keys stored in a `YubiHSM2` hardware device, via the
//!   `yubihsm-rs` crate.
//!
//! ## Signing API
//!
//! Signatory provides the following convenience methods for signing. Each of
//! them dispatches through a trait object for the given trait:
//!
//! - [signatory::sign] - sign a byte slice using a given signing provider.
//!   This method wraps the [Signer] trait and is most useful for computing
//!   [ed25519] signatures.
//! - [signatory::sign_digest] - sign the given precomputed digest using the
//!   given signing provider, a.k.a. Initialize-Update-Finalize (IUF). This
//!   method wraps the [DigestSigner] trait and is most useful for signing
//!   large messages in conjunction with hardware-backed signers.
//! - [signatory::sign_sha256], [signatory::sign_sha384],
//!   [signatory::sign_sha512] - sign the given message after first computing
//!   its SHA-2 digest. These methods wrap the [Sha256Signer],
//!   [Sha384Signer], and [Sha512Signer] traits respectively, and are most
//!   useful in conjunction with [ecdsa].
//!
//! Each of these methods and traits is generic around the signature type.
//! This makes it important to annotate the particular type of signature
//! which you would like when using them, e.g.
//!
//! ```
//! use signatory::{self, ed25519};
//!
//! let sig: ed25519::Signature = signatory::sign(signer, &msg).unwrap();
//! ```
//!
//! Or use the [turbofish]:
//!
//! ```
//! use signatory::{self, ed25519};
//!
//! let sig = signatory::sign::<ed25519::Signature>(signer, &msg).unwrap();
//! ```
//!
//! Alternatively, for Ed25519 signatures, the [ed25519] module provides
//! methods which operate on concrete Ed25519 types.
//!
//! ## Verifier API
//!
//! Signatory provides the following convenience methods for verifying
//! signatures, which map 1:1 to the methods provided for signing:
//!
//! * [signatory::verify] - verify a byte slice using a given provider.
//!   This method wraps the [Verifier] trait and is most useful for verifying
//!   [ed25519] signatures.
//! * [signatory::verify_digest] - verify the given precomputed message digest
//!   against the provided signature, i.e. IUF. This method wraps the
//!   [DigestVerifier] trait and is most useful for verifying large messages
//!   in conjunction with hardware-backed signers.
//! * [signatory::verify_sha256], [signatory::verify_sha384],
//!   [signatory::verify_sha512] - verify the given message after first
//!   computing its SHA-2 digest. These methods wrap the [Sha256Verifier],
//!   [Sha384Verifier], and [Sha512Verifier] traits respectively, and are most
//!   useful in conjunction with [ecdsa].
//!
//! [FIPS 186-4]: https://csrc.nist.gov/publications/detail/fips/186/4/final
//! [RFC 8032]: https://tools.ietf.org/html/rfc8032
//! [ecdsa]: https://docs.rs/signatory/latest/signatory/ecdsa/index.html
//! [ed25519]: https://docs.rs/signatory/latest/signatory/ed25519/index.html
//! [signatory-dalek]: https://docs.rs/crate/signatory-dalek/
//! [signatory-ring]: https://docs.rs/crate/signatory-ring/
//! [signatory-secp256k1]: https://docs.rs/crate/signatory-secp256k1/
//! [signatory-sodiumoxide]: https://docs.rs/crate/signatory-sodiumoxide/
//! [signatory-yubihsm]:  https://docs.rs/crate/signatory-yubihsm/
//! [signatory::sign]: https://docs.rs/signatory/latest/signatory/fn.sign.html
//! [signatory::sign_digest]: https://docs.rs/signatory/latest/signatory/fn.sign_digest.html
//! [signatory::sign_sha256]: https://docs.rs/signatory/latest/signatory/fn.sign_sha256.html
//! [signatory::sign_sha384]: https://docs.rs/signatory/latest/signatory/fn.sign_sha384.html
//! [signatory::sign_sha512]: https://docs.rs/signatory/latest/signatory/fn.sign_sha512.html
//! [Signer]: https://docs.rs/signatory/latest/signatory/trait.Signer.html
//! [DigestSigner]: https://docs.rs/signatory/latest/signatory/trait.DigestSigner.html
//! [Sha256Signer]: https://docs.rs/signatory/latest/signatory/trait.Sha256Signer.html
//! [Sha384Signer]: https://docs.rs/signatory/latest/signatory/trait.Sha384Signer.html
//! [Sha512Signer]: https://docs.rs/signatory/latest/signatory/trait.Sha512Signer.html
//! [signatory::verify]: https://docs.rs/signatory/latest/signatory/fn.verify.html
//! [signatory::verify_digest]: https://docs.rs/signatory/latest/signatory/fn.verify_digest.html
//! [signatory::verify_sha256]: https://docs.rs/signatory/latest/signatory/fn.verify_sha256.html
//! [signatory::verify_sha384]: https://docs.rs/signatory/latest/signatory/fn.verify_sha384.html
//! [signatory::verify_sha512]: https://docs.rs/signatory/latest/signatory/fn.verify_sha512.html
//! [Verifier]: https://docs.rs/signatory/latest/signatory/trait.Verifier.html
//! [DigestVerifier]: https://docs.rs/signatory/latest/signatory/trait.DigestVerifier.html
//! [Sha256Verifier]: https://docs.rs/signatory/latest/signatory/trait.Sha256Verifier.html
//! [Sha384Verifier]: https://docs.rs/signatory/latest/signatory/trait.Sha384Verifier.html
//! [Sha512Verifier]: https://docs.rs/signatory/latest/signatory/trait.Sha512Verifier.html
//! [turbofish]: https://turbo.fish/

#![crate_name = "signatory"]
#![crate_type = "lib"]
#![no_std]
#![cfg_attr(
    all(feature = "nightly", not(feature = "std")),
    feature(alloc)
)]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tendermint/signatory/master/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory/0.9.3"
)]

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(feature = "digest")]
pub extern crate digest;
#[cfg(feature = "generic-array")]
pub extern crate generic_array;
#[cfg(feature = "rand")]
extern crate rand;
#[cfg(feature = "sha2")]
extern crate sha2;
#[cfg(feature = "encoding")]
pub extern crate subtle_encoding;
#[cfg(feature = "zeroize")]
extern crate zeroize;

#[macro_use]
pub mod error;

#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "ed25519")]
#[macro_use]
pub mod ed25519;
#[cfg(feature = "encoding")]
pub mod encoding;
pub(crate) mod prelude;
mod public_key;
mod signature;
mod signer;
#[cfg(feature = "test-vectors")]
pub mod test_vector;
mod util;
mod verifier;

#[cfg(feature = "digest")]
pub use digest::Digest;
#[cfg(feature = "ecdsa")]
pub use ecdsa::{
    curve, PublicKey as EcdsaPublicKey, SecretKey as EcdsaSecretKey, Signature as EcdsaSignature,
};
#[cfg(feature = "ed25519")]
pub use ed25519::{
    PublicKey as Ed25519PublicKey, Seed as Ed25519Seed, Signature as Ed25519Signature,
};
#[cfg(feature = "encoding")]
pub use encoding::*;
pub use error::{Error, ErrorKind};
pub use public_key::{public_key, PublicKey, PublicKeyed};
pub use signature::Signature;
#[cfg(feature = "digest")]
pub use signer::digest::sign_digest;
pub use signer::*;
pub use signer::{
    sha2::{sign_sha256, sign_sha384, sign_sha512},
    sign,
};
#[cfg(feature = "digest")]
pub use verifier::digest::verify_digest;
pub use verifier::*;
pub use verifier::{
    sha2::{verify_sha256, verify_sha384, verify_sha512},
    verify,
};
