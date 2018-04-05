//! Trait for Ed25519 signers

use error::Error;
use super::{PublicKey, Signature};

/// Trait for Ed25519 signers (object-safe)
pub trait Signer: Sync {
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey, Error>;

    /// Compute an Ed25519 signature for the given message
    fn sign(&self, msg: &[u8]) -> Result<Signature, Error>;
}
