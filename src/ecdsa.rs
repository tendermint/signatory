//! The Elliptic Curve Digital Signature Algorithm (ECDSA) as specified in
//! FIPS 186-4 (Digital Signature Standard)

mod public_key;
mod secret_key;

pub use self::{public_key::PublicKey, secret_key::SecretKey};

// Use signature and curve types from the `ecdsa` crate
pub use ::ecdsa::{curve, generic_array, Asn1Signature, Curve, FixedSignature};

#[cfg(feature = "test-vectors")]
pub use ::ecdsa::test_vectors;
