//! Ed25519: Schnorr signatures using the twisted Edwards form of Curve25519
//!
//! Described in RFC 8032: <https://tools.ietf.org/html/rfc8032>

mod public_key;
mod signature;
mod signer;
mod verifier;

/// RFC 8032 Ed25519 test vectors
#[cfg(test)]
mod test_vectors;

pub use self::public_key::{PublicKey, PUBLIC_KEY_SIZE};
pub use self::signature::{Signature, SIGNATURE_SIZE};
pub use self::signer::Signer;
pub use self::verifier::{DefaultVerifier, Verifier};

#[cfg(test)]
pub use self::test_vectors::TEST_VECTORS;
