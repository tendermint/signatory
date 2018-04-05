//! Signatory: a multi-provider digital signature library

#![crate_name = "signatory"]
#![crate_type = "lib"]
#![no_std]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(html_root_url = "https://docs.rs/yubihsm/0.3.2")]

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(feature = "dalek-provider")]
extern crate ed25519_dalek;
#[cfg(feature = "ring-provider")]
extern crate ring;
#[cfg(feature = "dalek-provider")]
extern crate sha2;
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
