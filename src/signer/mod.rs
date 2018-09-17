//! Signing API for Signatory providers

#[cfg(feature = "digest")]
pub(crate) mod digest;
pub(crate) mod sha2;

use error::Error;
use Signature;

#[cfg(feature = "digest")]
pub use self::digest::*;
pub use self::sha2::*;

/// Trait for all signers which accept a message (byte slice) and produce a
/// signature of that message using this signer's private key.
pub trait Signer<S: Signature>: Send + Sync {
    /// Sign the given byte slice with this signer's private key, returning a
    /// signature.
    fn sign(&self, msg: &[u8]) -> Result<S, Error>;
}

/// Sign the given message slice with the given signer (alias for `sign_bytes`)
#[inline]
pub fn sign<S>(signer: &Signer<S>, msg: &[u8]) -> Result<S, Error>
where
    S: Signature,
{
    signer.sign(msg)
}
