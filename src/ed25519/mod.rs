//! Ed25519: Schnorr signatures using the twisted Edwards form of Curve25519
//!
//! Described in RFC 8032: <https://tools.ietf.org/html/rfc8032>

mod public_key;
mod seed;
mod signature;
mod signer;
mod verifier;

#[cfg(test)]
#[macro_use]
mod test_macros;

/// RFC 8032 Ed25519 test vectors
#[cfg(feature = "test-vectors")]
mod test_vectors;

pub use self::public_key::{PublicKey, PUBLIC_KEY_SIZE};
pub use self::seed::{Seed, SEED_SIZE};
pub use self::signature::{Signature, SIGNATURE_SIZE};
pub use self::signer::{FromSeed, Signer};
#[cfg(feature = "test-vectors")]
pub use self::test_vectors::TEST_VECTORS;
pub use self::verifier::{DefaultVerifier, Verifier};
