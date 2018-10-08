//! Signatory ECDSA and Ed25519 provider for *ring*

#![crate_name = "signatory_ring"]
#![crate_type = "lib"]
#![no_std]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tendermint/signatory/master/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory-ring/0.9.0"
)]

extern crate ring;
#[cfg_attr(all(test, feature = "ed25519"), macro_use)]
extern crate signatory;
extern crate untrusted;
#[cfg(test)]
#[macro_use]
extern crate std;

/// ECDSA signing and verification support
#[cfg(feature = "ecdsa")]
pub mod ecdsa;

/// Ed25519 signing and verification support
#[cfg(feature = "ed25519")]
pub mod ed25519;
