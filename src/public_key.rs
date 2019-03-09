//! Traits for public keys

use crate::error::Error;
use core::fmt::Debug;

/// Signers which know their public keys (to be implemented by Signatory
/// providers)
pub trait PublicKeyed<K: PublicKey>: Send + Sync {
    /// Public key which can verify signatures created by this signer
    fn public_key(&self) -> Result<K, Error>;
}

/// Common trait for all public keys
pub trait PublicKey: AsRef<[u8]> + Debug + Sized + Eq + Ord {}

/// Get the public key for the given public keyed object (i.e. a `Signer`)
pub fn public_key<K: PublicKey>(keyed: &dyn PublicKeyed<K>) -> Result<K, Error> {
    keyed.public_key()
}
