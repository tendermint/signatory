//! Signatory: a multi-provider digital signature library
//!
//! This crate provides a thread-and-object-safe API for both creating and
//! verifying elliptic curve digital signatures, using either software-based
//! or hardware-based providers.
//!
//! Ed25519 ([RFC 8032]) is presently the only digital signature algorithm supported
//!
//! [RFC 8032]: https://tools.ietf.org/html/rfc8032
//!
//! There are several backend providers available, which need to be enabled
//! using Cargo features. For more information, please see the `providers`
//! module documentation. A brief summary of available providers follows:
//!
//! * `dalek-provider`: Ed25519 signing/verification using the pure-Rust
//!   ed25519-dalek crate. This provider is enabled-by-default.
//! * `ring-provider`: Ed25519 signing/verification with the *ring*
//!   cryptography library.
//! * `sodiumoxide-provider`: Ed25519 signing/verification with the
//!   sodiumoxide crate, a Rust wrapper for libsodium (NOTE: requires
//!   libsodium to be installed on the system)
//! * `yubihsm-provider`: Ed25519 signing-only using private keys stored in
//!   a `YubiHSM2` hardware device, via the yubihsm-rs crate.

#![crate_name = "signatory"]
#![crate_type = "lib"]
#![no_std]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(html_root_url = "https://docs.rs/yubihsm/0.4.0")]

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(feature = "dalek-provider")]
extern crate ed25519_dalek;
#[cfg(feature = "ring-provider")]
extern crate ring;
#[cfg(feature = "dalek-provider")]
extern crate sha2;
#[cfg(feature = "sodiumoxide-provider")]
extern crate sodiumoxide;
#[cfg(feature = "ring-provider")]
extern crate untrusted;
#[cfg(feature = "yubihsm-provider")]
extern crate yubihsm;

#[macro_use]
mod macros;

pub mod ed25519;
pub mod error;
pub mod providers;
pub mod test_vector;

pub use error::Error;
