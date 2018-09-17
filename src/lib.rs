//! Signatory: a multi-provider digital signature library
//!
//! This crate provides a thread-and-object-safe API for both creating and
//! verifying elliptic curve digital signatures, using either software-based
//! or hardware-based providers.
//!
//! ECDSA ([FIPS 186-4]) and Ed25519 ([RFC 8032]) are the supported digital
//! signature algorithms.
//!
//! [FIPS 186-4]: https://csrc.nist.gov/publications/detail/fips/186/4/final
//! [RFC 8032]: https://tools.ietf.org/html/rfc8032
//!
//! There are several backend providers available, which are each available
//! in their own crates:
//!
//! * [signatory-dalek]: Ed25519 signing/verification using the pure-Rust
//!   ed25519-dalek crate. This provider is enabled-by-default.
//! * [signatory-ring]: Ed25519 signing/verification with the *ring*
//!   cryptography library.
//! * [signatory-secp256k1]: ECDSA signing/verification for the secp256k1
//!    elliptic curve (commonly used by Bitcoin and other cryptocurrrencies)
//!    which wraps the libsecp256k1 library from Bitcoin Core.
//! * [signatory-sodiumoxide]: Ed25519 signing/verification with the
//!   sodiumoxide crate, a Rust wrapper for libsodium (NOTE: requires
//!   libsodium to be installed on the system)
//! * [signatory-yubihsm]: Ed25519 signing-only provider using private keys
//!   stored in a `YubiHSM2` hardware device, via the yubihsm-rs crate.
//!
//! [signatory-dalek]: https://crates.io/crates/signatory-dalek
//! [signatory-ring]: https://crates.io/crates/signatory-ring
//! [signatory-secp256k1]: https://crates.io/crates/signatory-secp256k1
//! [signatory-sodiumoxide]: https://crates.io/crates/signatory-sodiumoxide
//! [signatory-yubihsm]: https://crates.io/crates/signatory-yubihsm

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
    html_root_url = "https://docs.rs/signatory/0.9.0-alpha2"
)]

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(any(feature = "encoding", feature = "ed25519"))]
extern crate clear_on_drop;
#[cfg(feature = "digest")]
pub extern crate digest;
#[cfg(feature = "generic-array")]
pub extern crate generic_array;
#[cfg(feature = "rand")]
extern crate rand;
#[cfg(feature = "sha2")]
extern crate sha2;

#[macro_use]
pub mod error;

#[cfg(feature = "ecdsa")]
pub mod curve;
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
pub use ecdsa::{EcdsaPublicKey, EcdsaSignature};
#[cfg(feature = "ed25519")]
pub use ed25519::{Ed25519PublicKey, Ed25519Signature, Seed as Ed25519Seed};
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
