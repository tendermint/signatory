//! Unified signing API for all Signatory providers

pub(crate) mod bytes;
#[cfg(all(feature = "digest", feature = "generic-array"))]
pub(crate) mod digest;
pub(crate) mod sha2;

use error::Error;
use Signature;

#[cfg(all(feature = "digest", feature = "generic-array"))]
pub use self::digest::{DigestOutput, DigestSigner};
pub use self::{bytes::ByteSigner, sha2::Sha256Signer};

/// Common trait for all signature providers
pub trait Signer<M, S: Signature>: Send + Sync {
    /// Sign the given message with this signer's private key, returning a
    /// signature.
    ///
    /// This trait should be implemented for the message type which is closest
    /// to the provider's own API.
    fn sign(&self, msg: M) -> Result<S, Error>;
}
