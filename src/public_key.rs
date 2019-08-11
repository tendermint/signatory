//! Traits for public keys

use core::fmt::Debug;
use signature::Error;

/// Signers which know their public keys (to be implemented by Signatory
/// providers)
pub trait PublicKeyed<K: PublicKey>: Send + Sync {
    /// Public key which can verify signatures created by this signer
    fn public_key(&self) -> Result<K, Error>;
}

/// Common trait for all public keys
pub trait PublicKey: AsRef<[u8]> + Debug + Sized + Eq + Ord {}
