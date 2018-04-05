//! Ed25519: Schnorr signatures using the twisted Edwards form of Curve25519
//!
//! Described in RFC 8032: <https://tools.ietf.org/html/rfc8032>

mod public_key;
mod signature;
mod signer;
mod verifier;

/// RFC 8032 Ed25519 test vectors
mod test_vectors;

/// Size of the "seed" value for an Ed25519 private key
pub const SEED_SIZE: usize = 32;

pub use self::public_key::{PublicKey, PUBLIC_KEY_SIZE};
pub use self::signature::{Signature, SIGNATURE_SIZE};
pub use self::signer::Signer;
pub use self::verifier::{DefaultVerifier, Verifier};
pub use self::test_vectors::TEST_VECTORS;
