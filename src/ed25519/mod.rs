//! Ed25519: Schnorr signatures using the twisted Edwards form of Curve25519
//!
//! Described in RFC 8032: <https://tools.ietf.org/html/rfc8032>

mod public_key;
mod seed;
mod signature;

#[macro_use]
mod test_macros;

/// RFC 8032 Ed25519 test vectors
#[cfg(feature = "test-vectors")]
mod test_vectors;

#[cfg(feature = "test-vectors")]
pub use self::test_vectors::TEST_VECTORS;
pub use self::{
    public_key::{Ed25519PublicKey, PUBLIC_KEY_SIZE},
    seed::{FromSeed, Seed, SEED_SIZE},
    signature::{Ed25519Signature, SIGNATURE_SIZE},
};
