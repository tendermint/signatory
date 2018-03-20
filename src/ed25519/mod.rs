//! Ed25519: Schnorr signatures using the twisted Edwards form of Curve25519
//!
//! Described in RFC 8032: <https://tools.ietf.org/html/rfc8032>

mod public_key;
mod signature;

use error::Error;

/// RFC 8032 Ed25519 test vectors
#[cfg(test)]
mod test_vectors;

pub use self::public_key::{PublicKey, PUBLIC_KEY_SIZE};
pub use self::signature::{Signature, SIGNATURE_SIZE};

#[cfg(test)]
pub use self::test_vectors::TEST_VECTORS;

/// Parent trait for Ed25519 signers
/// Signer is an object-safe trait for producing a particular type of signature
pub trait Signer: Sync {
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey, Error>;

    /// Compute an Ed25519 signature for the given message
    fn sign(&self, msg: &[u8]) -> Result<Signature, Error>;
}
