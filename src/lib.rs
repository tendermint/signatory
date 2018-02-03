//! Signatory: a multi-provider digital signature library

#![crate_name = "signatory"]
#![crate_type = "lib"]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![no_std]

extern crate ed25519_dalek;
extern crate sha2;

pub mod ed25519;
pub mod error;

pub use error::Error;

/// Signature test vector
pub struct TestVector {
    /// Secret key (i.e. seed)
    pub sk: &'static [u8],

    /// Public key in compressed Edwards-y form
    pub pk: &'static [u8],

    /// Message to be signed
    pub msg: &'static [u8],

    /// Expected signature
    pub sig: &'static [u8],
}
