//! Verifier API for Signatory providers

#[cfg(feature = "digest")]
pub(crate) mod digest;
pub(crate) mod sha2;

use error::Error;
use Signature;

#[cfg(feature = "digest")]
pub use self::digest::*;
pub use self::sha2::*;

/// Trait for all verifiers which accept a message (byte slice) and signature
pub trait Verifier<S: Signature>: Send + Sync {
    /// Verify the signature against the given message byte slice
    /// using the public key this verifier was instantiated with.
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error>;
}

/// Verify the given message (byte slice) with the given `Verifier`.
#[inline]
pub fn verify<S>(verifier: &Verifier<S>, msg: &[u8], sig: &S) -> Result<(), Error>
where
    S: Signature,
{
    verifier.verify(msg, sig)
}
