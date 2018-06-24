//! Trait for Ed25519 signers

use super::{PublicKey, Signature, SEED_SIZE};
use error::Error;
/// Trait for Ed25519 signers that can be initialized from a seed value
pub trait FromSeed: Sized {
    /// Create a new Ed25519 signer from a seed (i.e. unexpanded private key)
    ///
    /// Seed values are 32-bytes of uniformly random data. This is in contrast
    /// to an Ed25519 keypair, which is 64-bytes and includes both the seed
    /// value and the public key.
    fn from_seed(seed: &[u8]) -> Result<Self, Error>;
}

/// Trait for Ed25519 signer to generate keys
pub trait KeyGen {
    /// Generate a random key using either Os entropy or HSM provided entropy
    fn generate_key() -> Self;

    ///Return the generated key seed as bytes
    fn seed_as_bytes(&self) -> &[u8; SEED_SIZE];
}

/// Trait for Ed25519 signers (object-safe)
pub trait Signer: Send + Sync {
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey, Error>;

    /// Compute an Ed25519 signature for the given message
    fn sign(&self, msg: &[u8]) -> Result<Signature, Error>;
}
