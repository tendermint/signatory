//! Unified verifier API for all Signatory providers

use core::fmt::Debug;

pub(crate) mod bytes;
#[cfg(all(feature = "digest", feature = "generic-array"))]
pub(crate) mod digest;
pub(crate) mod sha2;

use error::Error;
use Signature;

#[cfg(all(feature = "digest", feature = "generic-array"))]
pub use self::digest::DigestVerifier;
pub use self::{bytes::ByteVerifier, sha2::Sha256Verifier};

/// Common trait for all signature providers
pub trait Verifier<M, S: Signature>: Debug + Send + Sync {
    /// Sign the given message with this signer's private key, returning a
    /// signature.
    ///
    /// This trait should be implemented for the message type which is closest
    /// to the provider's own API.
    fn verify(&self, msg: M, signature: &S) -> Result<(), Error>;
}
